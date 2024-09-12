import json
import signal
import sys
import threading
from abc import ABC

from gym import Env
import numpy
import time
import subprocess
from loguru import logger
import xml.etree.ElementTree as ET
from gym import spaces
from hashlib import md5
from .PlayStoreDownloader import *
from selenium.common.exceptions import InvalidElementStateException, WebDriverException, \
    StaleElementReferenceException, NoSuchElementException, ElementNotVisibleException
from appium.webdriver.common.touch_action import TouchAction
from sniffer.bltlog_analyzer import BltLogAnalyzer
from sniffer.sniffer import Sniffer
from frida_hooker.frida_hooker import FridaHooker
from target_methods_hooker.target_methods_hooker import dex_type_to_java_type
from .utils.utils import Utils
from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from func_timeout import func_timeout
from func_timeout.exceptions import FunctionTimedOut
from .sink_watcher import SinkWatcher
from ui.config import *
import socket
from .utils import apk_analyzer

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from payload_agent.env import PayloadEnv
from payload_agent.algorithms.RandomExploration import RandomAlgorithm
from payload_agent.algorithms.SACExploration import SACAlgorithm
from payload_agent.algorithms.TRPOExploration import TRPOAlgorithm

from collections import deque
import networkx as nx
import configparser
import traceback
import enum
import frida
import re
import os

adb_path: str = Utils.get_adb_executable_path()

layout_config = configparser.ConfigParser()
layout_config.read(os.path.abspath(os.path.dirname(__file__)) + os.sep + "config.ini")
with open(os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))) + os.sep + "config.json", "r") \
        as f:
    config = json.load(f)

app_execution_logs_file = layout_config['DEFAULT']['app_log_trace_file']

app_package_name_re_pattern = r"<PKG>(.+)</PKG>"
queue_lock = threading.Lock()
all_methods_called = []
methods_called = []
methods_called_complete = []
ignored_methods = list()
iot_device_execution_trace_file_lock = threading.Lock()
exec_output_file_lock = threading.Lock()

separators = {'cls': ['<CLS>', '</CLS>'],
              'met': ['<MET>', '</MET>'],
              'par': ['<PARS>', '</PARS>'],
              'new_par': '<NEWPAR>',
              'ret': ['<RETTYPE>', '</RETTYPE>'],
              'next_entry': '<NEXT_ENTRY>',
              'new_class_field': '<NEW_CLS_FIELD>',
              'class_field': ['<CLS_FIELD>', '</CLS_FIELD>'],
              'field_name': ['<NAME>', '</NAME>'],
              'field_value': ['<VAL>', '</VAL>'],
              'time': ['<TIMESTAMP>', '</TIMESTAMP>'],
              'pkg_name': ['<PKG>', '</PKG>']
              }


def search_package_and_setprop(folder, udid):
    """
    result = subprocess.run(
        [adb_path, "shell", "su", "0", "find", "/data/data/", "-type", "d", "-name", f'"{package}*"'],
        capture_output=True)
    folder = result.stdout.decode('utf-8').strip('\n')
    """
    command = f'{adb_path} -s {udid} shell "su 0 setprop jacoco.destfile /data/data/{folder}/jacoco.exec"'
    os.popen(command).read()


def collect_coverage_emma(udid, package, coverage_dir, coverage_count):
    os.system(f'{adb_path} -s {udid} shell am broadcast -p {package} -a edu.gatech.m3.emma.COLLECT_COVERAGE')
    os.system(
        f'{adb_path} -s {udid} pull /mnt/sdcard/coverage.ec {os.path.join("test", coverage_dir, str(coverage_count))}.ec')


def collect_coverage_jacoco(udid, package, coverage_dir, coverage_count):
    os.system(f'{adb_path} -s {udid} shell am broadcast -p {package} -a intent.END_COVERAGE')
    os.system(f'{adb_path} -s {udid} pull /sdcard/Android/data/{package}/files/coverage.ec '
              f'{os.path.join("test", coverage_dir, str(coverage_count))}.ec')


def method_to_string(cls, method, params, ret, pkg_name):
    return separators['cls'][0] + cls + separators['cls'][1] + separators['met'][0] + method + \
        separators['met'][1] + separators['par'][0] + separators['new_par'].join(params) + \
        separators['par'][1] + separators['ret'][0] + ret + separators['ret'][1] + \
        separators['pkg_name'][0] + pkg_name + separators['pkg_name'][1]


def string_to_method(method_str):
    cls = re.search(f"{separators['cls'][0]}(.*){separators['cls'][1]}", method_str).group(1)
    method = re.search(f"{separators['met'][0]}(.*){separators['met'][1]}", method_str).group(1)
    params = re.search(f"{separators['par'][0]}(.*){separators['par'][1]}", method_str).group(1)
    ret = re.search(f"{separators['ret'][0]}(.*){separators['ret'][1]}", method_str).group(1)

    param_list = []
    for par in params.split(separators['new_par']):
        param_list.append(par)

    method_computed = (cls, method, tuple(param_list), ret)

    return method_computed


def on_destroyed():
    time.sleep(2)
    logger.error("on_destroyed called")
    queue_lock.acquire()
    try:
        if len(methods_called) > 0:
            method_to_ignore = string_to_method(methods_called[-1])
            ignored_methods.append(method_to_ignore)
    finally:
        queue_lock.release()


def start_log_server(host, port, log_file, lock):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    while True:
        client_socket, client_address = server_socket.accept()
        with open(log_file, 'a') as f:
            while True:
                try:
                    message = client_socket.recv(1024)
                    if not message:
                        break
                    decoded_message = message.decode('utf-8')

                    lock.acquire()
                    try:
                        f.write(f"{decoded_message}\n")
                    finally:
                        lock.release()
                except ConnectionResetError:
                    print(f"Connection lost with {client_address}")
                    break

        client_socket.close()


class HookingException(Exception):
    pass


class RLAlgorithms(enum.Enum):
    Sac = 'SAC'
    Q = 'Q'
    Random = 'random'
    Trpo = 'TRPO'
    RecurrentPPO = 'RecurrentPPO'
    A2C = "A2C"


class LayoutEnv(Env, ABC):

    def __init__(self, coverage_dict, firmware_name, firmware_mapping_path, smartphone_apk_path, smartwatch_apk_path,
                 reinstall_app, list_activities, widget_list, coverage_dir, working_dir_layout, log_dir_layout,
                 working_dir_payload, log_dir_payload, rotation, internet, button_menu, platform_name, platform_version,
                 smartphone_udid, smartwatch_udid, instr_emma, instr_jacoco, device_name, main_activity,
                 exported_activities, services, receivers, permissions, is_headless, appium, emulator, package,
                 pool_strings, pool_passwords, hooker: FridaHooker, visited_activities: list, clicked_buttons: list,
                 appium_port, install_app_from_store: bool, target_methods: dict, paths_to_sinks: dict, episode: int,
                 app_call_graph: nx.DiGraph, intermediate_methods_to_hook: set, sink_methods_to_hook: set,
                 sink_activities: set, sink_services: set, sink_broadcast: set, listeners: set, fragments: set,
                 network_monitor_app_package_name: str, output_file_path: str, sink_reachability_rew: bool,
                 sink_network_rew: bool, min_distance_to_sink_rew: bool, new_activity_rew: bool, sniffer: Sniffer,
                 DELTA: float, MAX_REWARD: float, reward_sink_reached: float, reward_activity: float,
                 reward_service: float, reward_broadcast: float, reward_sink_activity: float,
                 reward_sink_service: float, iteration_count: int,
                 reward_sink_broadcast: float, reward_view: float, good_distance_reward: float,
                 config_payload_agent: str, rce_file_count: int,
                 bad_distance_reward: float, iot_device_execution_trace_path: str, rce_call_log: str,
                 bltlog_analyzer: BltLogAnalyzer, max_episode_len=250, string_activities='', log_for_tests=False,
                 instr=False, OBSERVATION_SPACE=2000, ACTION_SPACE=30):

        self.no_interactable_views = False
        all_methods_called.clear()
        methods_called.clear()
        methods_called_complete.clear()

        self.firmware_name = firmware_name
        self.firmware_mapping_path = firmware_mapping_path
        self.iteration_count = iteration_count
        self.install_app_from_store = install_app_from_store
        self.config_payload_agent = configparser.ConfigParser()
        self.config_payload_agent.read(config_payload_agent)
        self.rce_file_count = rce_file_count
        self.platform_name = platform_name
        self.platform_version = platform_version
        self.device_name = device_name
        self.activity_before_step = None
        self.current_activity = None
        self.dims = None
        self.package = package
        self.pid = None
        self.sink_reached_event = None
        self.sink_watcher = None
        self.hooker = hooker
        self.reinstall_app = reinstall_app
        self.sink_broadcast = sink_broadcast
        self.sink_services = sink_services
        self.sink_activities = sink_activities
        self.listeners = listeners
        self.fragments = fragments
        self.main_activity = main_activity
        self.script = None
        logger.debug("Calling RLApplicationEnv()")
        self.intermediate_methods_to_hook = intermediate_methods_to_hook
        self.sink_methods_to_hook = sink_methods_to_hook
        self.new_activity_rew = new_activity_rew
        self.sink_reachability_rew = sink_reachability_rew
        self.OBSERVATION_SPACE = OBSERVATION_SPACE
        self.ACTION_SPACE = ACTION_SPACE
        self.instr = instr
        self.emulator = emulator
        self.appium = appium
        #self.emulator.restart_emulator()

        self.exported_activities = deque(exported_activities)
        self.coverage_dir = coverage_dir
        self.working_dir_layout = working_dir_layout
        self.log_dir_layout = log_dir_layout
        self.working_dir_payload = working_dir_payload
        self.log_dir_payload = log_dir_payload
        self.smartphone_apk_path = smartphone_apk_path
        self.smartwatch_apk_path = smartwatch_apk_path
        self.appium_port = appium_port
        if instr_emma:
            self.instr = True
            self.instr_funct = collect_coverage_emma
        elif instr_jacoco:
            self.instr = True
            self.instr_funct = collect_coverage_jacoco

        self.rotation = rotation
        self.internet = internet
        self.button_menu = button_menu
        self.intents = services + receivers
        self.intent_flag = bool(len(self.intents))

        self.shift = self.internet + self.rotation + self.button_menu + self.intent_flag
        self.modify_internet_connection = int(self.internet) - 1
        self.do_rotation = self.internet + self.rotation - 1
        self.click_menu_button = self.internet + self.rotation + self.button_menu - 1
        self.intent_action = self.internet + self.rotation + self.button_menu + self.intent_flag - 1

        self.jacoco_package = package
        self.visited_activities = visited_activities
        self.clicked_buttons = clicked_buttons
        self.episode = episode
        self.connection = False
        self.strings = []
        self.coverage_count = 0
        self.observation = numpy.array([0] * self.OBSERVATION_SPACE)
        self._max_episode_steps = max_episode_len
        self.timesteps = 0
        self.outside = False
        self.outside_count = 0
        # Obtaining reference to external dictionary
        self.coverage_dict = coverage_dict
        self.widget_list = widget_list
        self.views = {}
        self.current_view = None
        self.iot_device_execution_trace_path = iot_device_execution_trace_path
        self.rce_call_log = rce_call_log

        self.logger_id = logger.add(os.path.join(self.log_dir_layout, 'action_logger.log'),
                                    format="{time} {level} {message}", level='DEBUG')

        logger.debug(self.firmware_name + ' START')

        self.list_activities = list_activities
        self.smartphone_udid = smartphone_udid
        self.smartwatch_udid = smartwatch_udid

        if float(platform_version) >= 5.0:
            automation_name = 'uiautomator2'
        else:
            automation_name = 'uiautomator1'

        with open(self.firmware_mapping_path, "r") as f:
            self.firmware_mapping = json.load(f)

        self.install_app("com.router.mdns",
                         os.path.join(os.path.abspath(os.path.dirname(__file__)), "support_apps",
                                      "com.router.mdns.apk"))

        subprocess.run(["adb", "-s", self.smartphone_udid, "shell", "am", "force-stop", "com.router.mdns"],
                       stderr=subprocess.DEVNULL)

        subprocess.run(["adb", "-s", self.smartphone_udid, "shell", "am", "broadcast", "-a",
                        "com.router.mdns.START_MDNS_SERVICE",
                        "-n", "com.router.mdns/com.router.mdns.receivers.MdnsReceiver",
                        "--es", "model_number", self.firmware_mapping[self.firmware_name]["model"]])

        #self.install_app_for_testing()
        self.appium.restart_appium()

        self.desired_caps = {'platformName': platform_name,
                             'platformVersion': platform_version,
                             'udid': smartphone_udid,
                             'appPackage': self.package,
                             'appActivity': main_activity,
                             'deviceName': device_name,
                             'autoLaunch': True,
                             'autoGrantPermissions': True,
                             'noReset': False,
                             'fullReset': False,
                             'unicodeKeyboard': True,
                             'resetKeyboard': True,
                             'androidInstallTimeout': 30000,
                             'isHeadless': is_headless,
                             'automationName': automation_name,
                             'adbExecTimeout': 30000,
                             'appWaitActivity': string_activities,
                             'newCommandTimeout': 200}

        while True:
            try:
                self.driver = webdriver.Remote(f'http://127.0.0.1:{self.appium_port}/wd/hub',
                                               self.desired_caps)
                break
            except Exception as e:
                logger.error(e)
                logger.error(traceback.format_exc())
                #self.emulator.restart_emulator()
                self.appium.restart_appium()
                #self.install_app_for_testing()
                #self.appium.restart_appium()

        self.previous_service = ''
        self.previous_broadcast = ''
        self.desired_caps['autoLaunch'] = False
        self.desired_caps.pop('appPackage')
        self.desired_caps.pop('appActivity')

        with open(os.path.abspath(os.path.dirname(__file__)) + os.sep + "agent.js", "r") as f:
            self.agent_cnt = f.read()

        # Finding all clickable elements, it updates self.views
        self._md5 = ''
        """
        try:
            func_timeout(20, self.get_all_views, args=())
        except FunctionTimedOut as e:
            logger.error(traceback.format_exc())
            self.manager(e)
        """
        # Used to get the reward during an episode
        self.set_activities_episode = {self.current_activity}
        self.set_views_episode = set()
        self.set_services_episode = set()
        self.set_broadcast_episode = set()
        # self.driver.implicitly_wait(0.3)
        # Opening String input
        with open(pool_strings, 'r+') as f:
            self.strings = f.read().split('\n')

        with open(pool_passwords, 'r+') as f:
            self.passwords = f.read().split('\n')

        # I suppose strings and password have the same length to limit action space complexity

        # Defining Gym Spaces
        self.action_space: spaces.Box = spaces.Box(low=numpy.array([0, 0, 0]),
                                                   high=numpy.array([self.ACTION_SPACE, len(self.strings) - 1, 1]),
                                                   dtype=numpy.int64)
        self.observation_space = spaces.Box(low=0, high=1, shape=(self.OBSERVATION_SPACE,), dtype=numpy.int32)
        # self.dims = self.driver.get_window_size()
        # self.activity_before_step = self.driver.current_activity
        # self.check_activity()
        self.target_methods = target_methods
        self.min_sink_distance_history = {sink: [] for sink in target_methods.keys()}
        self.app_call_graph = app_call_graph
        self.path_to_sinks = paths_to_sinks
        self.intermediate_methods_called = dict()
        self.method_to_sink_distances = dict()
        self.log_for_tests = log_for_tests
        self.output_file_path = output_file_path
        self.sink_network_rew = sink_network_rew
        self.min_distance_to_sink_rew = min_distance_to_sink_rew
        self.sniffer = sniffer

        self.app_name = smartphone_apk_path[smartphone_apk_path.rindex(os.sep) + 1:]
        self.network_monitor_app_package_name = network_monitor_app_package_name

        self.DELTA = DELTA
        self.MAX_REWARD = MAX_REWARD
        self.reward_sink_reached = reward_sink_reached
        self.reward_activity = reward_activity
        self.reward_service = reward_service
        self.reward_broadcast = reward_broadcast
        self.reward_sink_activity = reward_sink_activity
        self.reward_sink_broadcast = reward_sink_broadcast
        self.reward_sink_service = reward_sink_service
        self.reward_view = reward_view
        self.good_distance_reward = good_distance_reward
        self.bad_distance_reward = bad_distance_reward
        self.rl_model_saving_lock = threading.Lock()
        self.running_rewards_lock = threading.Lock()
        self.running_rewards = []

        self.blt_log_analyzer = bltlog_analyzer

        if not os.path.exists(self.log_dir_layout + os.sep + "action_log.txt"):
            with open(self.log_dir_layout + os.sep + "action_log.txt", "w+"):
                pass

        logger.debug("Granting all permissions")
        for permission in permissions:
            subprocess.call(["adb", "-s", self.smartphone_udid, "shell", "pm", "grant", self.package, permission],
                            stderr=subprocess.DEVNULL)

        services_receivers_permissions = set()
        for num in range(len(self.intents)):
            for perm_idx in range(len(self.intents[num]["permissions"])):
                services_receivers_permissions.add(self.intents[num]["permissions"][perm_idx])

        logger.debug("Granting Service and Receiver permissions")
        permissions_to_grant = permissions.difference(services_receivers_permissions)
        for permission in permissions_to_grant:
            subprocess.call(["adb", "-s", self.smartphone_udid, "shell", "pm", "grant", self.package, permission],
                            stderr=subprocess.DEVNULL)

        """
        if os.path.exists(self.smartwatch_apk_path):
            self.smartwatch_package, self.smartwatch_main_activity, _, _, _, _, _, _ = apk_analyzer.analyze(
                self.smartwatch_apk_path, {})
        """

        prefixes_file_path = os.path.abspath(self.config_payload_agent["DEFAULT"]["prefixes_file_path"])
        suffixes_file_path = os.path.abspath(self.config_payload_agent["DEFAULT"]["suffixes_file_path"])
        encoders_path = os.path.abspath(self.config_payload_agent["DEFAULT"]["encoders_path"])
        rce_to_file_path = os.path.abspath(self.config_payload_agent["DEFAULT"]["rce_to_file_path"])
        working_dir_payload = os.path.abspath(self.config_payload_agent["DEFAULT"]["working_dir"])
        max_timesteps = self.config_payload_agent["DEFAULT"]["max_timesteps"]
        reward_sink_reached = self.config_payload_agent["DEFAULT"]["reward_sink_reached"]
        reward_good_intermediate = self.config_payload_agent["DEFAULT"]["reward_good_intermediate"]
        reward_bad_intermediate = self.config_payload_agent["DEFAULT"]["reward_bad_intermediate"]
        reward_exploit_done = self.config_payload_agent["DEFAULT"]["reward_exploit_done"]
        reward_exploit_not_done = self.config_payload_agent["DEFAULT"]["reward_exploit_not_done"]
        max_num_sink_parameters = self.config_payload_agent["DEFAULT"]["max_num_sink_parameters"]
        php_files = os.path.abspath(self.config_payload_agent["DEFAULT"]["php_files"])
        self.payload_env = PayloadEnv(self, self.iot_device_execution_trace_path, self.log_dir_payload,
                                      self.firmware_name, self.firmware_mapping, int(max_num_sink_parameters),
                                      prefixes_file_path, suffixes_file_path, encoders_path, rce_to_file_path,
                                      self.package, working_dir_payload, self.episode, int(max_timesteps), php_files,
                                      reward_sink_reached, reward_good_intermediate, reward_bad_intermediate,
                                      reward_exploit_done, reward_exploit_not_done, self.rce_call_log,
                                      iot_device_execution_trace_file_lock, exec_output_file_lock)

        self.log_server_process = threading.Thread(target=start_log_server,
                                                   args=('0.0.0.0', 1234, self.iot_device_execution_trace_path,
                                                         iot_device_execution_trace_file_lock))
        self.log_server_process.start()

        self.rce_server_process = threading.Thread(target=start_log_server,
                                                   args=('0.0.0.0', 5678, self.rce_call_log, exec_output_file_lock))
        self.rce_server_process.start()

    def install_app(self, package_name_app, app_to_install_path):
        packages_installed = subprocess.Popen(["adb", "-s", self.smartphone_udid, "shell", "pm", "list",
                                               "packages"], stdout=subprocess.PIPE)
        out, _ = packages_installed.communicate()
        packages = out.decode()

        app_installed = False
        for package in packages.split("\n"):
            if package_name_app in package:
                app_installed = True
                break

        if not app_installed:
            subprocess.run(["adb", "-s", self.smartphone_udid, "install", "-r", "-t",
                            app_to_install_path])

    def install_app_for_testing(self):
        if self.reinstall_app:
            if self.install_app_from_store:
                install_try_counts = 0
                while install_try_counts < 3:
                    packages_installed = subprocess.Popen(["adb", "-s", self.smartphone_udid, "shell", "pm", "list",
                                                           "packages"], stdout=subprocess.PIPE)
                    out, _ = packages_installed.communicate()
                    packages = out.decode()

                    for package in packages.split("\n"):
                        if self.package in package:
                            logger.info(f"Uninstalling app: {self.package}")
                            subprocess.call(['adb', '-s', self.smartphone_udid, 'uninstall', self.package])
                            break

                    try:
                        #install_app(self.appium, self.package, os.path.dirname(self.smartphone_apk_path),
                        #            self.smartphone_udid, self.appium_port, self.platform_name, self.platform_version,
                        #            self.device_name)
                        break
                    except Exception as e:
                        logger.error(e)
                        logger.error(traceback.format_exc())
                        #self.emulator.restart_emulator()
                        install_try_counts += 1

                    if install_try_counts == 3:
                        logger.error(f"App {self.package} not installed")
                        return
            else:
                sm_p = subprocess.Popen(["adb", "-s", self.smartphone_udid, "install", "-r", "-t",
                                         self.smartphone_apk_path], stderr=subprocess.PIPE)
                out, err_sm = sm_p.communicate()

                if os.path.exists(self.smartphone_apk_path):
                    sw_p = subprocess.Popen(["adb", "-s", self.smartwatch_udid, "install", "-r", "-t",
                                             self.smartwatch_apk_path], stderr=subprocess.PIPE)
                    out, err_sw = sw_p.communicate()
                else:
                    err_sw = bytes()
                if len(err_sm) == 0 and len(err_sw) == 0:
                    return True
                return False

    def fix_method_tuple(self, method_tuple):
        if len(method_tuple) == 3:
            match = re.search(r"\('\((.*)\)', '(.+)'\)", str(method_tuple[2]))
            if match:
                params = match.group(1).split(" ") if match.group(1) != "" else []
                for i in range(len(params)):
                    params[i] = dex_type_to_java_type(params[i])
                ret = match.group(2)
                return (method_tuple[0], method_tuple[1], tuple(params), ret)
        return method_tuple

    def extract_methods_to_hook(self):
        intermediate_methods_to_hook_it = []
        to_delete = []
        self.intermediate_methods_to_hook = list(self.intermediate_methods_to_hook)
        for i in range(len(self.intermediate_methods_to_hook)):
            self.intermediate_methods_to_hook[i] = self.fix_method_tuple(self.intermediate_methods_to_hook[i])
            if len(self.intermediate_methods_to_hook[i]) != 4 and self.intermediate_methods_to_hook[i] not in to_delete:
                to_delete.append(self.intermediate_methods_to_hook[i])
                continue
            skip_method = False
            for param in self.intermediate_methods_to_hook[i][2]:
                if type(param) == tuple or type(param) == list:
                    to_delete.append(self.intermediate_methods_to_hook[i])
                    skip_method = True
                    break
            if skip_method:
                continue
            method = FridaHooker.frida_it(self.intermediate_methods_to_hook[i])
            if method not in ignored_methods:
                intermediate_methods_to_hook_it.append(method)
        for method in to_delete:
            self.intermediate_methods_to_hook.remove(method)
        self.intermediate_methods_to_hook = set(self.intermediate_methods_to_hook)

        sink_methods_to_hook_it = []
        to_delete = []
        self.sink_methods_to_hook = list(self.sink_methods_to_hook)
        for i in range(len(self.sink_methods_to_hook)):
            self.sink_methods_to_hook[i] = self.fix_method_tuple(self.sink_methods_to_hook[i])
            if len(self.sink_methods_to_hook[i]) != 4 and self.sink_methods_to_hook[i] not in to_delete:
                to_delete.append(self.sink_methods_to_hook[i])
                continue
            skip_method = False
            for param in self.sink_methods_to_hook[i][2]:
                if type(param) == tuple or type(param) == list:
                    to_delete.append(self.sink_methods_to_hook[i])
                    skip_method = True
                    break
            if skip_method:
                continue
            method = FridaHooker.frida_it(self.sink_methods_to_hook[i])
            if method not in ignored_methods:
                sink_methods_to_hook_it.append(method)
        for method in to_delete:
            self.sink_methods_to_hook.remove(method)
        self.sink_methods_to_hook = set(self.sink_methods_to_hook)

        listeners_it = []
        to_delete = []
        self.listeners = list(self.listeners)
        for i in range(len(self.listeners)):
            self.listeners[i] = self.fix_method_tuple(self.listeners[i])
            if len(self.listeners[i]) != 4 and self.listeners[i] not in to_delete:
                to_delete.append(self.listeners[i])
                continue
            skip_method = False
            for param in self.listeners[i][2]:
                if type(param) == tuple or type(param) == list:
                    to_delete.append(self.listeners[i])
                    skip_method = True
                    break
            if skip_method:
                continue
            method = FridaHooker.frida_it(self.listeners[i])
            if method not in ignored_methods:
                listeners_it.append(method)
        for method in to_delete:
            self.listeners.remove(method)
        self.listeners = set(self.listeners)

        fragments_it = []
        to_delete = []
        self.fragments = list(self.fragments)
        for i in range(len(self.fragments)):
            self.fragments[i] = self.fix_method_tuple(self.fragments)
            if len(self.fragments[i]) != 4 and self.fragments[i] not in to_delete:
                to_delete.append(self.fragments[i])
                continue
            skip_method = False
            for param in self.fragments[i][2]:
                if type(param) == tuple or type(param) == list:
                    to_delete.append(self.fragments[i])
                    skip_method = True
                    break
            if skip_method:
                continue
            logger.info(self.fragments[i])
            method = FridaHooker.frida_it(self.fragments[i])
            if method not in ignored_methods:
                fragments_it.append(method)
        for method in to_delete:
            self.fragments.remove(method)
        self.fragments = set(self.fragments)

        methods_to_hook = {}

        for intermediate_method in intermediate_methods_to_hook_it:
            cls = intermediate_method[0]
            method = intermediate_method[1]
            params = intermediate_method[2]
            ret = intermediate_method[3]
            hooking = method_to_string(cls, method, params, ret, self.package)

            methods_to_hook[hooking] = {}
            methods_to_hook[hooking]["type"] = ["INTERMEDIATE"]
            methods_to_hook[hooking]['cls'] = cls
            methods_to_hook[hooking]['method'] = method
            methods_to_hook[hooking]['params'] = params
            methods_to_hook[hooking]['ret'] = ret

        for sink in sink_methods_to_hook_it:
            cls = sink[0]
            method = sink[1]
            params = sink[2]
            ret = sink[3]
            hooking = method_to_string(cls, method, params, ret, "com.dlink.dlinkwifi")

            if hooking in methods_to_hook:
                methods_to_hook[hooking]["type"].append("SINK")
            else:
                methods_to_hook[hooking] = {}
                methods_to_hook[hooking]["type"] = ["SINK"]
                methods_to_hook[hooking]['cls'] = cls
                methods_to_hook[hooking]['method'] = method
                methods_to_hook[hooking]['params'] = params
                methods_to_hook[hooking]['ret'] = ret

        for listener in listeners_it:
            cls = listener[0]
            method = listener[1]
            params = listener[2]
            ret = listener[3]
            hooking = method_to_string(cls, method, params, ret, self.package)

            if hooking in methods_to_hook:
                methods_to_hook[hooking]["type"].append("LISTENER")
            else:
                methods_to_hook[hooking] = {}
                methods_to_hook[hooking]["type"] = ["LISTENER"]
                methods_to_hook[hooking]['cls'] = cls
                methods_to_hook[hooking]['method'] = method
                methods_to_hook[hooking]['params'] = params
                methods_to_hook[hooking]['ret'] = ret

        for fragment in fragments_it:
            cls = fragment[0]
            method = fragment[1]
            params = fragment[2]
            ret = fragment[3]
            hooking = method_to_string(cls, method, params, ret, self.package)

            if hooking in methods_to_hook:
                methods_to_hook[hooking]["type"].append("FRAGMENT")
            else:
                methods_to_hook[hooking] = {}
                methods_to_hook[hooking]["type"] = ["FRAGMENT"]
                methods_to_hook[hooking]['cls'] = cls
                methods_to_hook[hooking]['method'] = method
                methods_to_hook[hooking]['params'] = params
                methods_to_hook[hooking]['ret'] = ret

        return methods_to_hook

    def hook_app(self):
        def on_message(message, payload):
            if message["type"] == "send":
                if message['payload']["tag"] == 'CALLED':
                    queue_lock.acquire()
                    try:
                        methods_called.append(message["payload"]["payload"].strip())
                        methods_called_complete.append(message["payload"]["payload"].strip())
                    finally:
                        queue_lock.release()
                elif message['payload']["tag"] == 'ERROR':
                    method_tuple = string_to_method(message['payload']["payload"][7:].strip())
                    if method_tuple not in ignored_methods:
                        ignored_methods.append(method_tuple)
                elif message["payload"]["tag"] == 'PARAMETERS':
                    self.payload_env.layout_sink_method_called_signature = message["payload"]["sink"]

                    algo = self.config_payload_agent["DEFAULT"]["algo"]
                    timer = self.config_payload_agent["DEFAULT"]["timer"]

                    algorithm = None
                    if algo == RLAlgorithms.Random:
                        algorithm = RandomAlgorithm()
                    elif algo == RLAlgorithms.Sac:
                        algorithm = SACAlgorithm()
                    elif algo == RLAlgorithms.Trpo:
                        algorithm = TRPOAlgorithm()

                    if algorithm:
                        policy_dir = os.path.join(os.path.abspath(os.path.dirname(os.path.dirname(__file__))),
                                                  'payload_agent', 'policies', str(self.iteration_count),
                                                  str(self.episode))

                        os.makedirs(policy_dir, exist_ok=True)
                        self.payload_env.parameters_to_modify = json.loads(message["payload"]["payload"])
                        logger.info("Starting Paylod Agent")
                        flag = algorithm.explore(self.payload_env, self.emulator, self.timesteps, timer,
                                                 lock=self.rl_model_saving_lock, save_policy=True,
                                                 reload_policy=True, app_name=self.package,
                                                 policy_dir=policy_dir, cycle=self.episode)

                        if len(self.payload_env.reward_history) > 0:
                            self.running_rewards_lock.acquire()
                            try:
                                self.running_rewards.append(self.payload_env.reward_history[-1])
                            finally:
                                self.running_rewards_lock.release()

                        if flag:
                            with open(f'{self.log_dir_payload}{os.sep}success.log', 'a+') as f:
                                f.write(f'{self.package}\n')
                        else:
                            with open(f'{self.log_dir_payload}{os.sep}error.log', 'a+') as f:
                                f.write(f'{self.package}\n')

        logger.debug("Attaching Frida Process")
        count_hook_failed = 0
        methods_to_hook = self.extract_methods_to_hook()
        while count_hook_failed < 5:
            try:
                device = frida.get_device(self.smartphone_udid)
                pid = self.get_app_process()
                if pid:
                    device.kill(pid)
                    time.sleep(1)

                with open(os.path.abspath(os.path.dirname(__file__)) + os.sep + "pkg_name.txt", "w+") as f:
                    f.write(self.package)

                subprocess.run(["adb", "-s", self.smartphone_udid, "push",
                                os.path.abspath(os.path.dirname(__file__)) + os.sep + "pkg_name.txt",
                                "/data/local/tmp"], stdout=subprocess.DEVNULL)

                with open(os.path.abspath(os.path.dirname(__file__)) + os.sep + "methods.json", "w+") as f:
                    json.dump(methods_to_hook, f)

                subprocess.run(["adb", "-s", self.smartphone_udid, "push",
                                os.path.abspath(os.path.dirname(__file__)) + os.sep + "methods.json",
                                "/data/local/tmp"], stdout=subprocess.DEVNULL)

                pid = device.spawn([self.package])
                device.resume(pid)
                time.sleep(1)

                session = device.attach(pid)
                self.script = session.create_script(self.agent_cnt)
                self.script.on("message", on_message)
                #self.script.on("destroyed", on_destroyed)
                self.script.load()
                logger.debug("Frida Process Attached")
                break
            except Exception as e:
                logger.error(e)
                logger.error(traceback.format_exc())
                count_hook_failed += 1
                if count_hook_failed >= 5:
                    raise HookingException("")

    def start_app_test(self):
        try:
            self.driver.press_keycode(3)
            self.driver.quit()
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())
            #self.emulator.restart_emulator()
            self.appium.restart_appium()
            #self.install_app_for_testing()
            #self.appium.restart_appium()

        try:
            self.hook_app()
        except HookingException as e:
            raise e

        while True:
            try:
                self.driver = webdriver.Remote(f'http://127.0.0.1:{self.appium_port}/wd/hub', self.desired_caps)
                break
            except Exception as e:
                logger.error(e)
                logger.error(traceback.format_exc())
                #self.emulator.restart_emulator()
                self.appium.restart_appium()
                #self.install_app_for_testing()
                #self.appium.restart_appium()

        """
        if os.path.exists(self.smartwatch_apk_path):
            subprocess.run(["adb", "-s", self.smartwatch_udid, "shell", "am", "start", "-n",
                            self.smartwatch_package + "/" + self.smartwatch_main_activity])
        """

    def get_app_process(self):
        count = 0
        while count < 5:
            try:
                device = frida.get_device(self.smartphone_udid)
                for a in device.enumerate_applications():
                    if a.identifier == self.package and a.pid:
                        return a.pid
                return None
            except Exception as e:
                logger.error(e)
                logger.error(traceback.format_exc())
                count += 1
                #self.emulator.restart_emulator()
                self.appium.restart_appium()
                #self.install_app_for_testing()
                #self.appium.restart_appium()

            if count > 0:
                while True:
                    try:
                        self.driver = webdriver.Remote(f'http://127.0.0.1:{self.appium_port}/wd/hub', self.desired_caps)
                        break
                    except Exception as e:
                        logger.error(e)
                        logger.error(traceback.format_exc())
                        #self.emulator.restart_emulator()
                        self.appium.restart_appium()
                        #self.install_app_for_testing()
                        #self.appium.restart_appium()
        return None

    def write_test_logs(self, log_message: str):
        with open(self.log_dir_layout + os.sep + self.output_file_path, "a") as f:
            f.write(log_message + "\n")

    @logger.catch()
    def step(self, action_number):
        try:
            self.activity_before_step = self.driver.current_activity
            action_number = action_number.astype(int)
            if action_number[0] >= self.get_action_space()[0]:
                with open(self.log_dir_layout + os.sep + "action_log.txt", "a") as f:
                    f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>"
                            f"<ACT>Not Valid Action</ACT><OBS>{self.activity_before_step}</OBS>"
                            f"<REW>{-150.0}</REW><DONE>{False}</DONE><INFO>{json.dumps({})}</INFD>\n")
                done = self._termination()
                return self.observation, -150.0, numpy.array(done), {}
            else:
                self.timesteps += 1
                action_str, view_str, observation, reward, done, info = self.step2(action_number)
                with open(self.log_dir_layout + os.sep + "action_log.txt", "a") as f:
                    f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>"
                            f"<ACT>{action_str}</ACT><OBS>{self.activity_before_step}</OBS>"
                            f"{f'<VIEW>{view_str}</VIEW>' if view_str != '' else ''}<REW>{reward}</REW><DONE>{done}"
                            f"</DONE><INFO>{json.dumps(info)}</INFD>\n")
                return observation, reward, done, info
        except StaleElementReferenceException:
            done = self._termination()
            with open(self.log_dir_layout + os.sep + "action_log.txt", "a") as f:
                f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>"
                        f"<ACT>Error Action</ACT><OBS>{self.activity_before_step}</OBS>"
                        f"<REW>{-50.0}</REW><DONE>{done}</DONE><INFO>{json.dumps({})}</INFD>\n")
            return self.observation, -50.0, numpy.array(done), {}
        except NoSuchElementException:
            done = self._termination()
            with open(self.log_dir_layout + os.sep + "action_log.txt", "a") as f:
                f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>"
                        f"<ACT>Error Action</ACT><OBS>{self.activity_before_step}</OBS>"
                        f"<REW>{-50.0}</REW><DONE>{False}</DONE><INFO>{json.dumps({})}</INFD>\n")
            return self.observation, -50.0, numpy.array(done), {}
        except ElementNotVisibleException:
            done = self._termination()
            with open(self.log_dir_layout + os.sep + "action_log.txt", "a") as f:
                f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>"
                        f"<ACT>Error Action</ACT><OBS>{self.activity_before_step}</OBS>"
                        f"<REW>{-50.0}</REW><DONE>{done}</DONE><INFO>{json.dumps({})}</INFD>\n")
            return self.observation, -50.0, numpy.array(done), {}
        except WebDriverException as e:
            logger.error(e)
            logger.error(traceback.format_exc())
            return self.manager(e)
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())
        finally:
            if not os.path.exists(self.log_dir_layout + os.sep + app_execution_logs_file[:-4] + "_reward.txt"):
                with open(self.log_dir_layout + os.sep + app_execution_logs_file[:-4] + "_reward.txt", "w+"):
                    pass

            queue_lock.acquire()
            try:
                with open(self.log_dir_layout + os.sep + app_execution_logs_file[:-4] + "_reward.txt", "a") as f:
                    for line in methods_called:
                        f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>{line}\n")
                methods_called.clear()
            finally:
                queue_lock.release()

    def step2(self, action_number):
        view_str = ''
        self.current_view = None
        #self.sniffer.start_capturing_app_traffic(self.log_dir_layout)
        try:
            if not self.get_app_process():
                self.start_app_test()

            # We do a system action
            if self.internet and (action_number[0] == self.modify_internet_connection):
                logger.debug('set connection to ' + str(self.connection))
                self.connection_action()
                action_str = "Modify Internet Connection"
            # We do a system action
            elif self.rotation and (action_number[0] == self.do_rotation):
                logger.debug('set orientation, original was ' + self.driver.orientation)
                self.orientation()
                time.sleep(0.2)
                try:
                    self.dims = self.driver.get_window_size()
                except Exception as e:
                    logger.error(e)
                    logger.error(traceback.format_exc())
                action_str = "Rotate Device"
            elif self.button_menu and (action_number[0] == self.click_menu_button):
                logger.debug('pressed menu button')
                self.driver.press_keycode(82)
                action_str = "Press Menu Button"
            elif self.intent_flag and (action_number[0] == self.intent_action):
                mod = action_number[1] % len(self.intents)
                action_str, err = self.generate_intent(mod)
                if len(err) > 0:
                    done = self._termination()
                    return f"Error: {action_str}", view_str, self.observation, -200.0, numpy.array(done), {}
            else:
                action_number[0] = action_number[0] - self.shift
                if len(self.views) == 0:
                    action_str = self.perform_touch_action(action_number)
                    time.sleep(0.05)
                else:
                    self.current_view = self.views[action_number[0]]

                    # Do Action
                    action_str, view_str = self.action(self.current_view, action_number)
                    logger.debug(f'action: {action_str} on {view_str}')
                    time.sleep(0.2)
            self.outside = self.check_activity()
            if self.outside:
                if self.outside_count < 2:
                    self.outside = False
                    self.outside_count += 1
                    # We need to reset the application
                    if self.driver.current_activity is None:
                        logger.debug("Restart Main Activity")
                        app_process = self.get_app_process()
                        if not app_process:
                            self.start_app_test()
                        else:
                            subprocess.call(["adb", "-s", self.smartphone_udid, "shell", "am", "start", "-n",
                                             self.package + "/" + self.main_activity])

                            """
                            if os.path.exists(self.smartwatch_apk_path):
                                subprocess.run(["adb", "-s", self.smartwatch_udid, "shell", "am", "start", "-n",
                                                self.smartwatch_package + "/" + self.smartwatch_main_activity])
                            """
                            time.sleep(3)
                        self.update_views()
                        done = self._termination()
                        return "Error Action", view_str, self.observation, -200.0, numpy.array(done), {}
                    # You should not use an activity named launcher ( ಠ ʖ̯ ಠ)
                    elif 'launcher' in self.driver.current_activity.lower():
                        logger.debug("Restart Main Activity")
                        app_process = self.get_app_process()
                        if not app_process:
                            self.start_app_test()
                        else:
                            subprocess.call(["adb", "-s", self.smartphone_udid, "shell", "am", "start", "-n",
                                             self.package + "/" + self.main_activity])

                            """
                            if os.path.exists(self.smartwatch_apk_path):
                                subprocess.run(["adb", "-s", self.smartwatch_udid, "shell", "am", "start", "-n",
                                                self.smartwatch_package + "/" + self.smartwatch_main_activity])
                            """
                            time.sleep(3)
                        self.update_views()
                        done = self._termination()
                        return "Error Action", view_str, self.observation, -200.0, numpy.array(done), {}
                else:
                    # logger.debug("Press Back Button")
                    self.outside_count = 0
                    app_process = self.get_app_process()
                    if not app_process:
                        self.start_app_test()
                    else:
                        subprocess.call(["adb", "-s", self.smartphone_udid, "shell", "am", "start", "-n",
                                         self.package + "/" + self.main_activity])

                        """
                        if os.path.exists(self.smartwatch_apk_path):
                            subprocess.run(["adb", "-s", self.smartwatch_udid, "shell", "am", "start", "-n",
                                            self.smartwatch_package + "/" + self.smartwatch_main_activity])
                        """
                        time.sleep(3)
                    self.update_views()
                    done = self._termination()
                    return "Error Action", view_str, self.observation, -200.0, numpy.array(done), {}
            self.get_observation()
            reward_layout = self.compute_reward(action_number)
            time.sleep(20)
            self.running_rewards_lock.acquire()
            try:
                if len(self.running_rewards) > 0:
                    reward = reward_layout + 0.4 * max(self.running_rewards)
                    self.running_rewards = []
                else:
                    reward = reward_layout
            finally:
                self.running_rewards_lock.release()
            if self.intent_flag and (action_number[0] == self.intent_action):
                mod = action_number[1] % len(self.intents)
                if self.intents[mod]['type'] == 'service':
                    self.previous_service = self.intents[mod]["name"]
                else:
                    self.previous_broadcast = self.intents[mod]["name"]
            done = self._termination()
            return action_str, view_str, self.observation, reward, numpy.array(done), {}
        except StaleElementReferenceException as e:
            self.update_views()
            raise e
        except NoSuchElementException as e:
            self.update_views()
            raise e
        except ElementNotVisibleException as e:
            self.update_views()
            raise e
        except HookingException:
            done = self._termination()
            return "Hooking Error", view_str, self.observation, 0.0, numpy.array(done), {}
        except Exception:
            logger.error(traceback.format_exc())
            self.update_views()
            done = self._termination()
            return "Error Action", view_str, self.observation, -200.0, numpy.array(done), {}
        finally:
            pass
            #self.sniffer.stop_capturing_app_traffic()
            #if os.path.exists(self.working_dir_layout + os.sep + 'dump.pcap'):
            #    os.remove(self.working_dir_layout + os.sep + 'dump.pcap')

    def action(self, current_view, action_number):
        action_str = "No Action"
        view_str = current_view['class_name']
        try:
            # If element is android.widget.EditText
            if current_view['class_name'] == 'android.widget.EditText':
                try:
                    current_view['view'].clear()
                    current_view['view'].click()
                    if current_view['password'] == 'false':
                        current_string = self.strings[action_number[1]]
                        current_view['view'].send_keys(current_string)
                        logger.debug('put string: ' + current_string)
                        action_str = f"Insert String in EditText: {current_string}"
                    else:
                        current_string = self.passwords[action_number[1]]
                        current_view['view'].send_keys(current_string)
                        logger.debug('put password: ' + current_string)
                        action_str = f"Insert Password in EditText: {current_string}"
                except InvalidElementStateException:
                    logger.debug('Impossible to insert string')
                    pass

            else:
                # If element is CLICKABLE
                if current_view['clickable'] == 'true' and current_view['long-clickable'] == 'false':
                    current_view['view'].click()
                    action_str = "Click View"

                # If element is both CLICKABLE and LONG-CLICKABLE
                elif current_view['clickable'] == 'true' and current_view['long-clickable'] == 'true':
                    if action_number[2] == 0:
                        current_view['view'].click()
                        action_str = "Click View"
                    else:
                        actions = TouchAction(self.driver)
                        actions.long_press(current_view['view'], duration=1000).release().perform()
                        action_str = "Long Click View"

                # If element is LONG-CLICKABLE
                elif current_view['clickable'] == 'false' and current_view['long-clickable'] == 'true':
                    actions = TouchAction(self.driver)
                    actions.long_press(current_view['view'], duration=1000).release().perform()
                    action_str = "Long Click View"

                # If element is SCROLLABLE
                elif current_view['scrollable'] == 'true':
                    bounds = re.findall(r'\d+', current_view['view'].get_attribute('bounds'))
                    bounds = [int(i) for i in bounds]
                    if (bounds[2] - bounds[0] > 20) and (bounds[3] - bounds[1] > 40):
                        self.scroll_action(action_number, bounds)
                        action_str = "Scroll View"
                    else:
                        pass

                elif self.no_interactable_views:
                    bounds = current_view['view'].rect
                    center_x = (bounds['x'] + bounds['width']) // 2
                    center_y = (bounds['y'] + bounds['height']) // 2
                    touch_action = TouchAction(self.driver)
                    if action_number[2] == 0:
                        touch_action.tap(None, x=center_x, y=center_y).perform()
                        action_str = "Click View"
                    else:
                        touch_action.long_press(None, x=center_x, y=center_y, duration=1000).release().perform()
                        action_str = "Long Click View"
        except StaleElementReferenceException:
            logger.error(traceback.format_exc())
            raise StaleElementReferenceException("")
        except NoSuchElementException:
            logger.error(traceback.format_exc())
            raise NoSuchElementException("")
        except ElementNotVisibleException:
            logger.error(traceback.format_exc())
            raise ElementNotVisibleException("")
        except Exception as e:
            logger.error(traceback.format_exc())
            raise e
        return action_str, view_str

    def compute_reward(self, action: list):
        time.sleep(2)
        self.sniffer.stop_capturing_app_traffic()
        try:
            if not self.get_app_process():
                return -200.0

            sinks_reached = self.get_methods_reached_type("SINK")
            if len(sinks_reached) > 0:
                if action[0] == self.intent_action:
                    mod = action[1] % len(self.intents)
                    if self.intents[mod]['type'] == 'service':
                        current_service = self.intents[mod]["name"]
                        self.sink_services.add(current_service)
                    else:
                        current_broadcast = self.intents[mod]["name"]
                        self.sink_broadcast.add(current_broadcast)
                else:
                    self.sink_activities.add(self.activity_before_step)

                _, _, first_sink_reached_ts = min(sinks_reached, key=lambda x: x[2])
                #bl_packet_ts = self.blt_log_analyzer.get_new_sent_packet_ts(first_sink_reached_ts)
                #network_packet_ts = self.sniffer.analyze_app_network_traffic(first_sink_reached_ts, self.working_dir_layout)

                if self.sink_network_rew:  # and bl_packet_ts is None and network_packet_ts is None:
                    for sink_tuple in sinks_reached:
                        self.write_test_logs(f"SINK REACHED: {sink_tuple[0]}<TIME>{sink_tuple[2]} "
                                             f"<STEP>{self.timesteps}<EPISODE>{self.episode}\n")
                    return self.MAX_REWARD
                #elif self.sink_reachability_rew:
                #    for sink_tuple in sinks_reached:
                #        self.write_test_logs(f"NETWORK: {sink_tuple[0]}<TIME>{sink_tuple[2]} "
                #                             f"<STEP>{self.timesteps}<EPISODE>{self.episode}\n")
                #    return self.MAX_REWARD
            reward = 0.0
            if self.min_distance_to_sink_rew:
                sink_distances = self.get_all_sinks_distances()
                if len(sink_distances) > 0:
                    sink, act_sink_dist = min(sink_distances.items(), key=lambda e: e[1])
                    if len(self.min_sink_distance_history[sink]) > 0:
                        prev_sink_dist = self.min_sink_distance_history[sink][-1]
                    else:
                        prev_sink_dist = 0
                    self.min_sink_distance_history[sink].append(act_sink_dist)
                    if (act_sink_dist - prev_sink_dist) > 0:
                        reward = self.good_distance_reward
                    else:
                        reward = self.bad_distance_reward

            listeners_reached = self.get_methods_reached_type("LISTENER")
            fragments_reached = self.get_methods_reached_type("FRAGMENT")
            if action[0] == self.intent_action:
                mod = action[1] % len(self.intents)
                if self.intents[mod]['type'] == 'service':
                    current_service = self.intents[mod]["name"]
                    if len(listeners_reached) > 0 or len(fragments_reached) > 0:
                        self.sink_services.add(current_service)

                    if current_service in self.sink_services and self.previous_service != current_service:
                        reward = reward + self.DELTA * self.reward_sink_service

                    if current_service not in self.set_services_episode:
                        self.set_services_episode.add(current_service)
                        reward = reward + self.DELTA * self.reward_service
                    else:
                        reward = reward - self.DELTA * self.reward_service
                else:
                    current_broadcast = self.intents[mod]["name"]
                    if len(listeners_reached) > 0 or len(fragments_reached) > 0:
                        self.sink_broadcast.add(current_broadcast)

                    if current_broadcast in self.sink_broadcast and self.previous_broadcast != current_broadcast:
                        reward = reward + self.DELTA * self.reward_sink_broadcast

                    if current_broadcast not in self.set_broadcast_episode:
                        self.set_broadcast_episode.add(current_broadcast)
                        reward = reward + self.DELTA * self.reward_broadcast
                    else:
                        reward = reward - self.DELTA * self.reward_broadcast
            else:
                if len(listeners_reached) > 0 or len(fragments_reached) > 0:
                    self.sink_activities.add(self.activity_before_step)

                if self.current_activity in self.sink_activities and self.current_activity != self.activity_before_step:
                    reward = reward + self.DELTA * self.reward_sink_activity

                if self.current_activity not in self.set_activities_episode:
                    self.set_activities_episode.add(self.current_activity)
                    reward = reward + self.DELTA * self.reward_activity
                else:
                    reward = reward - self.DELTA * self.reward_activity

                if self.current_view is not None and self.current_view['identifier'] not in self.set_views_episode:
                    self.set_views_episode.add(self.current_view['identifier'])
                    reward = reward + self.DELTA * self.reward_view
                else:
                    reward = reward - self.DELTA * self.reward_view
            return reward
        except Exception:
            logger.error(traceback.format_exc())
            return 0.0

    def get_methods_reached_type(self, type_method):
        queue_lock.acquire()
        try:
            if len(methods_called) == 0:
                return []

            method_lines = []
            for line in methods_called:
                if line.startswith(type_method):
                    method_lines.append(line.split(type_method)[1])
        finally:
            queue_lock.release()

        cls_re_str = f"{separators['cls'][0]}(.+){separators['cls'][1]}"
        met_re_str = f"{separators['met'][0]}(.+){separators['met'][1]}"
        pars_re_str = f"{separators['par'][0]}(.+){separators['par'][1]}"
        ret_re_str = f"{separators['ret'][0]}(.+){separators['ret'][1]}"
        time_re_str = f"{separators['time'][0]}(.+){separators['time'][1]}"
        new_par_sep = separators['new_par']
        app_package_re_str = f"{separators['pkg_name'][0]}(.+){separators['pkg_name'][1]}"

        methods_reached = []
        for method_called in method_lines:
            cls = re.search(cls_re_str, method_called).group(1)
            method = re.search(met_re_str, method_called).group(1)

            param_list = None
            params_re = re.search(pars_re_str, method_called)
            if params_re:
                params_substring = params_re.group(1)
                param_list = tuple(params_substring.split(new_par_sep))
            ret = re.search(ret_re_str, method_called).group(1)
            time_method_called = re.search(time_re_str, method_called).group(1)

            if not param_list:
                param_list = tuple()

            methods_reached.append(
                (re.search(app_package_re_str, method_called).group(1), [cls, method, param_list, ret],
                 float(time_method_called)))
        return methods_reached

    def get_all_sinks_distances(self):
        queue_lock.acquire()
        try:
            if len(methods_called) == 0:
                return dict()

            intermediate_lines = []
            for line in methods_called:
                if line.startswith("INTERMEDIATE"):
                    intermediate_lines.append(line[12:])
        finally:
            queue_lock.release()

        sink_min_distances = dict()
        cls_re_str = f"{separators['cls'][0]}(.+){separators['cls'][1]}"
        met_re_str = f"{separators['met'][0]}(.+){separators['met'][1]}"
        pars_re_str = f"{separators['par'][0]}(.+){separators['par'][1]}"
        ret_re_str = f"{separators['ret'][0]}(.+){separators['ret'][1]}"
        new_par_sep = separators['new_par']
        for sink_triple in self.target_methods:
            for method_called in intermediate_lines:
                cls = re.search(cls_re_str, method_called).group(1)
                method_name = re.search(met_re_str, method_called).group(1)

                param_list = None
                params_re = re.search(pars_re_str, method_called)
                if params_re:
                    params_substring = params_re.group(1)
                    param_list = params_substring.split(new_par_sep)
                ret = re.search(ret_re_str, method_called).group(1)
                method_called_triple = (cls, method_name, [] if not param_list else param_list, ret)
                method_called_triple = self.hooker.our_notation(method_called_triple)
                method_called_triple[2] = tuple(method_called_triple[2])
                method_called_triple = tuple(method_called_triple)
                if method_called_triple not in self.intermediate_methods_called:
                    soot_method_called = self.from_list_to_soot_method(method_called_triple)
                    self.intermediate_methods_called[method_called_triple] = soot_method_called
                else:
                    soot_method_called = self.intermediate_methods_called[method_called_triple]
                if soot_method_called:
                    if (method_called_triple, sink_triple) not in self.method_to_sink_distances \
                            and nx.has_path(self.app_call_graph, soot_method_called, self.target_methods[sink_triple]):
                        method_to_sink_distance = nx.shortest_path_length(self.app_call_graph,
                                                                          source=soot_method_called,
                                                                          target=self.target_methods[sink_triple])

                        self.method_to_sink_distances[(method_called_triple, sink_triple)] = method_to_sink_distance

                if (method_called_triple, sink_triple) not in self.method_to_sink_distances:
                    self.method_to_sink_distances[(method_called_triple, sink_triple)] = float('inf')

            if len(self.method_to_sink_distances) > 0:
                sink_min_distances[sink_triple] = min(
                    [dist for (_, sink_d), dist in self.method_to_sink_distances.items()
                     if sink_d == sink_triple])
        return sink_min_distances

    def from_list_to_soot_method(self, list_method):
        for node in self.app_call_graph.nodes():
            if node.class_name == list_method[0] and node.name == list_method[1] and node.ret == list_method[3] \
                    and len(node.params) == len(list_method[2]):
                param_idx = 0
                while param_idx < len(node.params):
                    if node.params[param_idx] != list_method[2][param_idx]:
                        break
                    param_idx += 1

                if param_idx == len(node.params):
                    return node
        return None

    def reset(self):
        logger.debug('<--- EPISODE RESET --->')

        while True:
            try:
                self._md5 = ''
                if self.script:
                    if not os.path.exists(
                            self.log_dir_layout + os.sep + app_execution_logs_file[:-4] + "_complete.txt"):
                        with open(self.log_dir_layout + os.sep + app_execution_logs_file[:-4] + "_complete.txt", "w+"):
                            pass

                    if not os.path.exists(
                            self.log_dir_layout + os.sep + app_execution_logs_file[:-4] + "_called_complete.txt"):
                        with open(self.log_dir_layout + os.sep + app_execution_logs_file[:-4] + "_called_complete.txt",
                                  "w+"):
                            pass

                    queue_lock.acquire()
                    try:
                        with open(self.log_dir_layout + os.sep + app_execution_logs_file[:-4] + "_complete.txt",
                                  "a") as f:
                            for line in all_methods_called:
                                f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>{line}\n")
                        all_methods_called.clear()

                        with open(self.log_dir_layout + os.sep + app_execution_logs_file[:-4] + "_called_complete.txt",
                                  "a") as f:
                            for line in methods_called_complete:
                                f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>{line}\n")
                        methods_called_complete.clear()
                    finally:
                        queue_lock.release()

                if self.sink_watcher:
                    self.sink_watcher.stop_watcher()

                """
                subprocess.call(
                    ['adb', '-s', self.smartphone_udid, 'shell', 'am', 'start-foreground-service', '-e', 'action',
                     'start',
                     '-e', 'pcap_dump_mode', 'udp_exporter', '-e', 'collector_ip_address', '10.0.2.2', '-e',
                     'collector_port', '5123',
                     '-e', 'app_filter', self.package, '-n',
                     self.network_monitor_app_package_name + '.debug/' + self.network_monitor_app_package_name +
                     ".CaptureCtrlService"]
                )
                """

                exception = False
                try:
                    self.start_app_test()
                except Exception as e:
                    logger.error(e)
                    logger.error(traceback.format_exc())
                    exception = True
                    #self.emulator.restart_emulator()
                    self.appium.restart_appium()
                    #self.install_app_for_testing()
                    self.appium.restart_appium()
                    self.driver.quit()

                if exception:
                    while True:
                        try:
                            self.driver = webdriver.Remote(f'http://127.0.0.1:{self.appium_port}/wd/hub',
                                                           self.desired_caps)
                            break
                        except Exception as e:
                            logger.error(e)
                            logger.error(traceback.format_exc())
                            #self.emulator.restart_emulator()
                            #self.appium.restart_appium()
                            #self.install_app_for_testing()
                            self.appium.restart_appium()
                            self.driver.quit()

                # First initialization
                self.current_activity = self.rename_activity(self.driver.current_package, self.driver.current_activity)
                self.driver.implicitly_wait(0.3)
                self.dims = self.driver.get_window_size()
                self.activity_before_step = self.driver.current_activity

                self.sink_reached_event = threading.Event()
                self.sink_watcher = SinkWatcher(queue_lock, methods_called, self.sink_reached_event)
                self.sink_watcher.start_watcher()
                self.current_activity = self.rename_activity(self.driver.current_package, self.driver.current_activity)
                self.set_activities_episode = {self.current_activity}
                self.set_views_episode = set()
                self.outside = self.check_activity()
                self.get_observation()
                return self.observation

            except Exception as e:
                logger.error(e)
                logger.error(traceback.format_exc())
                continue

    def get_observation(self):
        observation_0 = self.one_hot_encoding_activities()
        observation_1 = self.one_hot_encoding_widgets()
        self.observation = numpy.array(observation_0 + observation_1)

    def one_hot_encoding_activities(self):
        activity_observation = [0] * len(self.list_activities)
        if self.current_activity in self.list_activities:
            index = self.list_activities.index(self.current_activity)
            activity_observation[index] = 1
        return activity_observation

    def one_hot_encoding_widgets(self):
        widget_observation = [0] * (self.OBSERVATION_SPACE - len(self.list_activities))
        for k, item in self.views.items():
            identifier = item['identifier']
            if identifier in self.widget_list:
                index = self.widget_list.index(identifier)
                widget_observation[index] = 1
        return widget_observation

    def check_activity(self):
        temp_activity = self.rename_activity(self.driver.current_package, self.driver.current_activity)
        if temp_activity is None or (self.package != self.driver.current_package
                                     and temp_activity != '.common.account.AccountPickerActivity') or \
                temp_activity.find('com.facebook.FacebookActivity') >= 0:
            return True
        # If we have changed the activity:
        elif self.current_activity != temp_activity:
            self.current_activity = temp_activity

        # Updating buttons
        try:
            self.update_views()
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())
            return False
        return False

    def update_views(self):
        i = 0
        max_iterations_count = 5
        while i < max_iterations_count:
            try:
                func_timeout(120, self.get_all_views, args=())
                break
            except StaleElementReferenceException:
                logger.error(traceback.format_exc())
                time.sleep(0.05)
                i += 1
                if i == max_iterations_count:
                    logger.error('Too Many times tried')
                    break
            except WebDriverException as e:
                logger.error(traceback.format_exc())
                self.manager(e)
            except FunctionTimedOut:
                logger.error(traceback.format_exc())
                time.sleep(0.05)
                i += 1
                if i == max_iterations_count:
                    logger.error('Too Many times tried')
                    break
        if len(self.views) == 0:
            self.action_space.high[0] = self.ACTION_SPACE
        else:
            self.action_space.high[0] = len(self.views) + self.shift

        if i == max_iterations_count:
            raise HookingException("")

    def get_all_views(self):
        # Searching for clickable elements in XML/HTML source page
        page = self.driver.page_source
        tree = ET.fromstring(page)
        page = page.replace('enabled="true"', '').replace('enabled="false"', '').replace('checked="false"', '') \
            .replace('checked="true"', '')
        temp_md5 = md5(page.encode()).hexdigest()
        if temp_md5 != self._md5:
            self._md5 = temp_md5
            elements = tree.findall(".//*[@clickable='true']") + tree.findall(".//*[@scrollable='true']") + \
                       tree.findall(".//*[@long-clickable='true']") + tree.findall(".//*[@password='true']")
            self.views = {}
            self.no_interactable_views = len(elements) == 0
            if len(elements) == 0:
                elements = tree.findall(".//*[@clickable='false']") + tree.findall(".//*[@scrollable='false']") + \
                           tree.findall(".//*[@long-clickable='false']") + tree.findall(".//*[@password='false']")
            tags = set([element.tag for element in elements])
            i = 0
            for tag in tags:
                elements = self.driver.find_elements(AppiumBy.CLASS_NAME, tag)
                for e in elements:
                    clickable = e.get_attribute('clickable')
                    scrollable = e.get_attribute('scrollable')
                    long_clickable = e.get_attribute('long-clickable')
                    password = e.get_attribute('password')
                    enabled = e.get_attribute('enabled')
                    view_id = e.get_attribute('resource-id')
                    bounds = re.findall(r'\d+', e.get_attribute('bounds'))
                    bounds = [int(i) for i in bounds]
                    if enabled and (self.no_interactable_views or (clickable == 'true') or (scrollable == 'true') or
                                    (long_clickable == 'true') or (password == 'true')):
                        if self.current_activity:
                            identifier = self.return_attribute(e)
                            self.views.update(
                                {i: {'id': view_id, 'view': e, 'identifier': identifier, 'class_name': tag,
                                     'clickable': clickable, 'scrollable': scrollable, 'bounds': bounds,
                                     'long-clickable': long_clickable, 'password': password}})
                        i += 1

    def get_action_space(self):
        return list(self.action_space.high)

    def get_observation_space(self):
        return list(self.observation_space.shape)

    def append_visited_activities_coverage(self):
        visited_activities, pressed_buttons = Utils.compute_coverage(self.coverage_dict)
        self.visited_activities.append(visited_activities)
        self.clicked_buttons.append(pressed_buttons)

    def _termination(self):
        if (self.timesteps >= self._max_episode_steps) or self.outside:
            self.outside = False
            return True
        else:
            return False

    def manager(self, e):
        logger.debug("Calling RLApplicationEnv::manager")
        if str(e).find('DOM') > -1:
            done = self._termination()
            with open(self.log_dir_layout + os.sep + "action_log.txt", "a") as f:
                f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>"
                        f"<ACT>Error Action</ACT><OBS>{self.activity_before_step}</OBS>"
                        f"<REW>{-0.0}</REW><DONE>{done}</DONE><INFO>{json.dumps({})}</INFD>\n")
            return self.observation, 0.0, numpy.array(done), {}
        else:
            logger.error(f'E: {e} in app {self.smartphone_apk_path}')
            try:
                self.driver.quit()
            except WebDriverException:
                logger.error(traceback.format_exc())
            self.appium.restart_appium()

            while True:
                try:
                    self.driver = webdriver.Remote(f'http://127.0.0.1:{self.appium_port}/wd/hub', self.desired_caps)
                    break
                except Exception:
                    logger.error(traceback.format_exc())
                    #self.emulator.restart_emulator()
                    #self.install_app_for_testing()
                    self.appium.restart_appium()

            time.sleep(5)
            with open(self.log_dir_layout + os.sep + "action_log.txt", "a") as f:
                f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>"
                        f"<ACT>Final Action</ACT><OBS>{self.activity_before_step}</OBS>"
                        f"<REW>{0.0}</REW><DONE>{True}</DONE><INFO>{json.dumps({})}</INFD>\n")
            return self.observation, 0.0, numpy.array(True), {}

    def return_attribute(self, my_view):
        attribute_fields = ['resource-id', 'content-desc']
        attribute = None
        for attr in attribute_fields:
            attribute = my_view.get_attribute(attr)
            if attribute is not None:
                break
        if attribute is None:
            attribute = self.current_activity + '.' + my_view.get_attribute('class') + '.'
            sub_node = my_view.find_elements(AppiumBy.CLASS_NAME, 'android.widget.TextView')
            if len(sub_node) > 0:
                attribute += sub_node[0].get_attribute('text')
            else:
                attribute += my_view.get_attribute('text')
        return attribute

    def connection_action(self):
        # Activate internet connection
        if self.connection:
            self.connection = False
            self.driver.set_network_connection(4)
        else:
            self.connection = True
            self.driver.set_network_connection(0)

    def orientation(self):
        orientation = self.driver.orientation
        if orientation == 'PORTRAIT':
            try:
                self.driver.orientation = 'LANDSCAPE'
            except InvalidElementStateException as e:
                logger.error(traceback.format_exc())
        else:
            try:
                self.driver.orientation = 'PORTRAIT'
            except InvalidElementStateException as e:
                logger.error(traceback.format_exc())

    def scroll_action(self, action_number, bounds):
        y = int((bounds[3] - bounds[1]))
        x = int((bounds[2] - bounds[0]) / 2)
        if action_number[2] == 0:
            try:
                self.driver.swipe(x, int(y * 0.3), x, int(y * 0.5), duration=200)
            except InvalidElementStateException:
                logger.error(f'swipe not performed start_position: ({x}, {y}), end_position: ({x}, {y + 20})')
        else:
            try:
                self.driver.swipe(x, int(y * 0.5), x, int(y * 0.3), duration=200)
            except InvalidElementStateException:
                logger.error(f'swipe not performed start_position: ({x}, {y + 20}), end_position: ({x}, {y})')

    def rename_activity(self, actual_package, actual_activity):
        if actual_activity is not None:
            if actual_activity == ".common.account.AccountPickerActivity":
                return actual_activity

            for activity in self.list_activities:
                if activity.endswith(actual_activity):
                    return activity
        # logger.debug("Actual activity not valid: " + actual_package + actual_activity)
        return None

    def perform_touch_action(self, action):
        try:
            act = TouchAction(self.driver)
            x = (self.dims['width'] - 1) * action[0] / (self.ACTION_SPACE - self.shift)
            y = (self.dims['height'] - 1) * action[1] / (len(self.strings) - 1)
            act.tap(x=x, y=y).perform()
            logger.debug(f'action: Touch Action at coordinates:{int(x)}, {int(y)} Activity: {self.current_activity}')
            action_str = f"Touch Action at coordinates:{int(x)}, {int(y)} Activity: {self.current_activity}"
            return action_str
        except Exception as e:
            logger.error(traceback.format_exc())

    def generate_intent(self, num):
        if len(self.intents[num]["action"]) > 0:
            if self.intents[num]['type'] == 'service':
                command_string = f'{adb_path} -s {self.smartphone_udid} shell am startservice -n ' \
                                 f'"{self.package}/{self.intents[num]["name"]}" -a "{self.intents[num]["action"][0]}"'
                action_str = f'Start Service: {self.package}/{self.intents[num]["name"]}'
            else:
                command_string = f'{adb_path} -s {self.smartphone_udid} shell am broadcast -n ' \
                                 f'"{self.package}/{self.intents[num]["name"]}" -a "{self.intents[num]["action"][0]}"'
                action_str = f'Broadcast Message: {self.package}/{self.intents[num]["name"]}'
            # in case there is more than one action
            self.intents[num]["action"].rotate(1)
        else:
            if self.intents[num]['type'] == 'service':
                command_string = f'{adb_path} -s {self.smartphone_udid} shell am startservice -n ' \
                                 f'"{self.package}/{self.intents[num]["name"]}"'
                action_str = f'Start Service: {self.package}/{self.intents[num]["name"]}'
            else:
                command_string = f'{adb_path} -s {self.smartphone_udid} shell am broadcast ' \
                                 f'-n "{self.package}/{self.intents[num]["name"]} '
                if len(self.intents[num]["permissions"]) > 0:
                    command_string += f'--receiver-permission {self.intents[num]["permissions"][0]}'
                action_str = f'Broadcast Message: {self.package}/{self.intents[num]["name"]}'
        queue_lock.acquire()
        try:
            self.sink_reached_event.clear()
        finally:
            queue_lock.release()
        p = subprocess.Popen(command_string, shell=True, stderr=subprocess.PIPE)
        _, err = p.communicate()
        queue_lock.acquire()
        try:
            self.sink_reached_event.wait(7)
            self.sink_reached_event.clear()
        finally:
            queue_lock.release()
        return action_str, err
