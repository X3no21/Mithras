import re
import shutil
import subprocess
import sys
import json
import signal
import time
import traceback
from enum import Enum

from src.sniffer.sniffer import Sniffer
from src.sniffer.bltlog_analyzer import BltLogAnalyzer
from src.methods_finder import SendFinder, SweetSpotFinder
from src.frida_hooker.frida_hooker import FridaHooker, FridaRunner, ApkExploded
from src.ui.core import ADBDriver
from src.arg_fuzzer.arg_fuzzer import ArgFuzzer
from src.soot_wrapper.lifter import Lifter
from src.node_filter.node_filter import NodeFilter
from src.target_methods_hooker.target_methods_hooker import TargetMethodsHooker
from src.layout_agent.test_application import TestApp, RLAlgorithms, EmuType
from src.layout_agent.utils.utils import EmulatorLauncher
from src.layout_agent.PlayStoreDownloader import *
from src.layout_agent.utils.utils import AppiumLauncher
from src.utils.apkdiff import count_diff
import configparser
from loguru import logger
import frida
import os

import jpype
import jpype.imports
from jpype.pickle import JPickler, JUnpickler
from jpype.types import *

RERAN_RECORD_PATH = '/tmp/reran.log'


class Phase(Enum):
    SETUP = 0
    RERAN = 1
    KEEPALIVE = 2
    MESSAGE_SENDER = 3
    FUZZING_CANDIDATES = 4
    MANUAL_FUZZING = 5
    FUZZING = 6

    def __lt__(self, other):
        return self.value < other.value

    def __le__(self, other):
        return self.value <= other.value

    def __gt__(self, other):
        return self.value > other.value

    def __ge__(self, other):
        return self.value >= other.value

    def __eq__(self, other):
        return self.value == other.value

    def __ne__(self, other):
        return not self.value == other.value


@FridaRunner
class IoTFuzzer:
    def __init__(self, config):
        self.config = config
        self.reran_record_path = self.config['reran_record_path']
        self.senders = self.config['send_functions'] if 'send_functions' in self.config else []
        self.automated_senders = []
        self.fuzzing_candidates = self.config['fuzzing_candidates'] if 'fuzzing_candidates' in self.config else []
        self.sp = self.config['sweet_spots'] if 'sweet_spots' in self.config else []
        self.phase = Phase.SETUP

        self.config_layout_runtime_path = os.path.dirname(self.config["cf_layout_path"]) + os.sep + "config.ini"
        self.config_payload_runtime_path = os.path.dirname(self.config["cf_payload_path"]) + os.sep + "config.ini"

        self.layout_config = configparser.ConfigParser()
        self.layout_config.read(self.config_layout_runtime_path)

        self.reinstall_app = False if int(self.layout_config['DEFAULT']['reinstall_app']) == 0 else True

        logger.debug("Building Reran Object")
        self.device_id = self.config['device_id']
        self.adbd = ADBDriver(device_id=self.config['device_id'])
        logger.debug("Done.")

        if not os.path.exists(self.config["smartphone_apk_path"]):
            logger.error(f"Apk {os.path.basename(self.config['smartphone_apk_path'])} not found in "
                         f"{os.path.dirname(self.config['smartphone_apk_path'])} folder")
            return

        from_play_store = False
        if self.reinstall_app:
            from_play_store = self.install_app_for_testing()

        if from_play_store:
            app_folder_list_proc = subprocess.Popen(
                ["adb", "-s", self.layout_config['DEFAULT']['smartphone_udid'], "shell", "su",
                 "-c", "ls", "/data/app"], stdout=subprocess.PIPE)
            app_folder_list = app_folder_list_proc.stdout.read().decode().strip().split("\n")

            for app_folder in app_folder_list:
                folder_proc = subprocess.Popen(
                    ["adb", "-s", self.layout_config['DEFAULT']['smartphone_udid'], "shell", "su",
                     "-c", "ls", "/data/app/" + app_folder], stdout=subprocess.PIPE)

                folder = folder_proc.stdout.read().decode().strip()
                if self.config['proc_name'] in folder:
                    time.sleep(5)
                    subprocess.call(
                        ["adb", "-s", self.layout_config['DEFAULT']['smartphone_udid'], "pull",
                         "/data/app/" + app_folder +
                         "/" + folder + "/" + "base.apk", os.path.dirname(self.config["smartphone_apk_path"])])

                    try:
                        diffs = count_diff(os.path.dirname(self.config["smartphone_apk_path"]) + os.sep + "base.apk",
                                           self.config["smartphone_apk_path"])
                    except:
                        diffs = 1

                    if diffs > 0:
                        subprocess.call(
                            ["mv", os.path.dirname(self.config["smartphone_apk_path"]) + os.sep + "base.apk",
                             self.config["smartphone_apk_path"]])

                        if os.path.exists(
                                os.path.abspath(os.path.dirname(__file__)) + os.sep + "pickle_apk_soot" + os.sep +
                                self.config['proc_name']):
                            subprocess.call(["rm",
                                             os.path.abspath(
                                                 os.path.dirname(__file__)) + os.sep + "pickle_apk_soot" + os.sep +
                                             self.config['proc_name']
                                             ])

                        if os.path.exists(
                                os.path.abspath(os.path.dirname(__file__)) + os.sep + "pickle_cfg_soot" + os.sep +
                                self.config['proc_name']):
                            subprocess.call(["rm",
                                             os.path.abspath(
                                                 os.path.dirname(__file__)) + os.sep + "pickle_cfg_soot" + os.sep +
                                             self.config['proc_name']
                                             ])

                    elif os.path.exists(os.path.dirname(self.config["smartphone_apk_path"]) + os.sep + "base.apk"):
                        subprocess.call(
                            ["rm", os.path.dirname(self.config["smartphone_apk_path"]) + os.sep + "base.apk"])
                    break

        self.lifter = None
        if not self.config['leaf_pickle']:
            logger.debug("Building lifter")
            self.create_lifter()

        logger.debug("Building node filter")
        self.nf = NodeFilter(self.config, lifter=self.lifter)

        logger.debug("Building Sniffer")
        self.sniffer = Sniffer(self.config)
        logger.debug("Done.")

        logger.debug("Building BltLogAnalyzer")
        self.bltlog_analyzer = BltLogAnalyzer(self.adbd)
        logger.debug("Done.")

        logger.debug("Building Hooker")
        self.hooker = FridaHooker(self.config, self.layout_config, self, self.reinstall_app,
                                  node_filter=self.nf)
        logger.debug("Done.")

        logger.debug("Building TargetMethodsHooker")
        self.target_methods_hooker = TargetMethodsHooker(self.config, self.layout_config, self.reinstall_app,
                                                         self.hooker, self.lifter)
        logger.debug("Done.")

        logger.debug("Building SendFinder")
        self.send_finder = SendFinder(self.config, sniffer=self.sniffer, hooker=self.hooker,
                                      bltlog_analyzer=self.bltlog_analyzer)
        logger.debug("Done.")

        logger.debug("Building SweetSpotFinder")
        self.sp_finder = SweetSpotFinder(self.config, hooker=self.hooker, node_lifter=self.nf)
        logger.debug("Done.")

        logger.debug("Building ArgFuzzer")
        self.arg_fuzzer = ArgFuzzer(self.config, hooker=self.hooker)
        logger.debug("Done.")

        signal.signal(signal.SIGINT, self.signal_handler)

        self.separators = {'cls': ['<CLS>', '</CLS>'],
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

    def install_app_for_testing(self):
        packages = self.adbd.adb_cmd(["shell", "pm", "list", "packages"])
        for package in packages[0].split("\n"):
            if self.config['proc_name'] in package:
                logger.info(f"Uninstalling app: {self.config['proc_name']}")
                self.adbd.adb_cmd(['uninstall', self.config['proc_name']])
                break

        if self.config['install_app_from_store']:
            install_try_counts = 0
            while install_try_counts < 3:
                try:
                    appium = AppiumLauncher(int(self.layout_config['DEFAULT']['appium_port']))
                    from_play_store = install_app(appium, self.config['proc_name'],
                                                  os.path.dirname(self.config['smartphone_apk_path']),
                                                  self.layout_config['DEFAULT']['smartphone_udid'],
                                                  int(self.layout_config['DEFAULT']['appium_port']), 'Android',
                                                  self.layout_config['DEFAULT']['android_v'],
                                                  self.layout_config['DEFAULT']['smartphone_name'])
                    return from_play_store
                except Exception:
                    logger.error(traceback.format_exc())
                    #self.emulator.restart_emulator()
                    install_try_counts += 1

            if install_try_counts == 3:
                logger.error(f"App {self.config['proc_name']} not installed")
                return False
        else:
            sm_p = subprocess.Popen(["adb", "-s", self.layout_config['DEFAULT']['smartphone_udid'], "install", "-r", "-t",
                                     self.config['smartphone_apk_path']], stderr=subprocess.PIPE)
            out, sm_err = sm_p.communicate()

            if os.path.exists(self.config['smartphone_apk_path']):
                sw_p = subprocess.Popen(["adb", "-s", self.layout_config['DEFAULT']['smartwatch_udid'], "install", "-r", "-t",
                                         self.config['smartphone_apk_path']], stderr=subprocess.PIPE)
                out, sw_err = sw_p.communicate()
            else:
                sw_err = bytes()
            if len(sm_err) == 0 and len(sw_err) == 0:
                return True
            return False

    def create_lifter(self):
        logger.info("Creating Lifter")
        os.makedirs(os.path.abspath(os.path.dirname(__file__)) + os.sep + "pickle_apk_soot", exist_ok=True)
        f = os.path.abspath(os.path.dirname(__file__)) + os.sep + "pickle_apk_soot" + os.sep + self.config['proc_name']
        self.lifter = Lifter(os.path.abspath(self.config['smartphone_apk_path']), input_format="apk",
                             android_sdk=self.config['android_sdk_platforms'], save_to_file=f)

    def run_reran(self):
        if not self.reran_record_path:
            self.hooker.spawn_apk_in_device()
            self.adbd.record_ui(RERAN_RECORD_PATH)
            self.reran_record_path = RERAN_RECORD_PATH
            self.hooker.instrumenting_app = False
            self.hooker.terminate()
        self.adbd.translate_events_log(self.reran_record_path)

    def detect_keep_alive(self):
        self.hooker.start()  # leaves=True)
        self.sniffer.detect_keepalive()
        # FIXME: enable if we want to ignore automatically called functions
        # called_methods = self.hooker.last_methods_called
        # [self.automated_senders.append(c) for c in called_methods if c not in self.automated_senders]
        self.hooker.instrumenting_app = False
        self.hooker.terminate()
        self.bltlog_analyzer.detect_keep_alives()

    def signal_handler(self, sig, _):
        if sig == signal.SIGINT:
            self.terminate()

    def terminate(self):
        logger.info("Terminating...")
        if self.phase == Phase.KEEPALIVE:
            self.sniffer.terminate()
        elif self.phase == Phase.MESSAGE_SENDER:
            self.send_finder.terminate()
        elif self.phase == Phase.FUZZING:
            self.arg_fuzzer.terminate()

    def hook_app(self, methods_to_hook):

        def on_message(message, payload):
            if message["type"] == "send" and not message["payload"].startswith("COMPLETE"):
                logger.info(message["payload"])

        logger.debug("Attaching Frida Process")
        hook_started = False
        while not hook_started:
            try:
                with open(os.path.abspath(os.path.dirname(__file__)) + os.sep + "src" + os.sep + "layout_agent" + os.sep
                          + "agent.js", "r") as f:
                    agent_cnt = f.read()

                device = frida.get_device(self.device_id)
                for a in device.enumerate_applications():
                    if a.identifier == self.config['proc_name'] and a.pid:
                        device.kill(a.pid)
                        time.sleep(1)
                        break
                pid = device.spawn([self.config['proc_name']])
                device.resume(pid)
                time.sleep(15)
                session = device.attach(pid)
                script = session.create_script(agent_cnt)
                script.on("message", on_message)
                script.load()
                script.exports.hooksinkmethods(self.config['proc_name'], methods_to_hook)
                logger.debug("Frida Process Attached")
                hook_started = True
                sys.stdin.read()
            except ApkExploded:
                logger.error(traceback.format_exc())
                logger.debug(f"hook_started: {hook_started}")

    def verify_hook_on_methods(self, methods):
        for i in range(len(methods)):
            methods[i] = list(methods[i])
            methods[i][2] = list(methods[i][2])
            methods[i] = FridaHooker.frida_it(methods[i])

        self.hooker.start(to_hook=methods, leaves=False, fast_hook=True, ignore=[])
        if self.hooker.fail_hook_count >= 10:
            logger.warning(f"App {self.config['proc_name']} intermediate methods failed hooking")
            methods = tuple()
        else:
            for i in range(len(methods)):
                methods[i] = self.hooker.our_notation(methods[i])
                methods[i][2] = tuple(methods[i][2])
                methods[i] = tuple(methods[i])
            methods = tuple(methods)
        return methods

    def method_to_string(self, cls, method, params, ret, pkg_name):
        return self.separators['cls'][0] + cls + self.separators['cls'][1] + self.separators['met'][0] + method + \
            self.separators['met'][1] + self.separators['par'][0] + self.separators['new_par'].join(params) + \
            self.separators['par'][1] + self.separators['ret'][0] + ret + self.separators['ret'][1] + \
            self.separators['pkg_name'][0] + pkg_name + self.separators['pkg_name'][1]

    def manual_app_hooking(self, sink_methods_to_hook, intermediate_methods_to_hook, listeners_to_hook,
                           fragments_to_hook):
        methods_to_hook = {}
        intermediate_methods_to_hook_it = [FridaHooker.frida_it(m) for m in list(intermediate_methods_to_hook)]
        sink_methods_to_hook_it = [FridaHooker.frida_it(m) for m in list(sink_methods_to_hook)]
        listeners_it = [FridaHooker.frida_it(m) for m in list(listeners_to_hook)]
        fragments_it = [FridaHooker.frida_it(m) for m in list(fragments_to_hook)]

        for intermediate_method in intermediate_methods_to_hook_it:
            cls = intermediate_method[0]
            method = intermediate_method[1]
            params = intermediate_method[2]
            ret = intermediate_method[3]
            hooking = self.method_to_string(cls, method, params, ret, self.config['proc_name'])

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
            hooking = self.method_to_string(cls, method, params, ret, self.config['proc_name'])

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
            hooking = self.method_to_string(cls, method, params, ret, self.config['proc_name'])

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
            hooking = self.method_to_string(cls, method, params, ret, self.config['proc_name'])

            if hooking in methods_to_hook:
                methods_to_hook[hooking]["type"].append("FRAGMENT")
            else:
                methods_to_hook[hooking] = {}
                methods_to_hook[hooking]["type"] = ["FRAGMENT"]
                methods_to_hook[hooking]['cls'] = cls
                methods_to_hook[hooking]['method'] = method
                methods_to_hook[hooking]['params'] = params
                methods_to_hook[hooking]['ret'] = ret

        self.hook_app(methods_to_hook)

    def run(self, phase=Phase.FUZZING):
        try:
            # reran run
            eval_stats = open('/tmp/stats_' + self.config['proc_name'], 'w')
            replay_ui_async = self.adbd.replay_ui_async

            # if phase >= Phase.RERAN:
            #     logger.info("Recording user interactions")
            #     self.phase = Phase.RERAN
            #     self.run_reran()

            # if phase >= Phase.KEEPALIVE:
            #     logger.info("Detecting keep-alive messages")
            #     self.phase = Phase.KEEPALIVE
            #     self.detect_keep_alive()

            if os.path.exists(self.config["results_path"] + os.sep + self.config["proc_name"] + os.sep + "all_senders.txt"):
                with open(self.config["results_path"] + os.sep + self.config["proc_name"] + os.sep + "all_senders.txt", "r") as f:
                    sender_lines = f.readlines()

                self.senders = []
                for line in sender_lines:
                    match = re.search(r"(.*)<SEP>(.*)<SEP>(.*)<SEP>(.*)", line)
                    if match:
                        class_name = match.group(1)
                        method_name = match.group(2)
                        params = match.group(3).split("<PARAM>")
                        ret = match.group(4)
                        self.senders.append([class_name, method_name, params, ret])


            if not self.senders and phase >= Phase.MESSAGE_SENDER:
                starting_time = time.time()
                logger.info("Finding send-message method")
                self.senders = self.send_finder.start(ran_fun=replay_ui_async, lifter=self.lifter,
                                                      ignore=self.automated_senders)

                if self.hooker.fail_hook_count >= 10:
                    logger.error(f"App {self.config['proc_name']} failed hooking")
                    return

                elapsed_time = time.time() - starting_time
                eval_stats.write('Time (s): {}\nSenders: {}\n'.format(str(elapsed_time), str(self.senders)))
                # logger.debug("Possible senders {}".format(str(self.senders)))
                os.makedirs(self.config["results_path"] + os.sep + self.config["proc_name"], exist_ok=True)
                with open(
                        self.config["results_path"] + os.sep + self.config["proc_name"] + os.sep + "all_senders.txt",
                        "w+") \
                        as f:
                    for sender in self.senders:
                        sender_copy = sender.copy()
                        sender_copy[2] = "<PARAM>".join(sender_copy[2])
                        sender_str = "<SEP>".join(sender_copy)
                        f.write(sender_str + "\n")

                with open(
                        self.config["results_path"] + os.sep + self.config["proc_name"] + os.sep + "hooked_senders.txt",
                        "w+") as f:
                    for sender in self.hooker.methods_hooked:
                        sender_copy = sender.copy()
                        sender_copy[2] = "<PARAM>".join(sender_copy[2])
                        sender_str = "<SEP>".join(sender_copy)
                        f.write(sender_str + "\n")

            logger.info("Searching paths to SINKS")
            cfg_path = os.path.abspath(os.path.dirname(__file__)) + os.sep + "pickle_cfg_soot" + os.sep + \
                                        self.config['proc_name']
            self.target_methods_hooker.start(self.config["smartphone_apk_path"], cfg_path, self.senders, [],
                                             [], hook_only_targets=False, lifter=self.lifter)
            with open(
                    self.config["results_path"] + os.sep + self.config[
                        "proc_name"] + os.sep + "reachable_senders.txt",
                    "w+") as f:
                for sender, paths in self.target_methods_hooker.paths_to_targets.items():
                    if len(paths) > 0:
                        sender_triple = [sender.class_name, sender.name, (param for param in sender.params),
                                         sender.ret]

                        sender_copy = sender_triple.copy()
                        sender_copy[2] = "<PARAM>".join(sender_copy[2])
                        sender_str = "<SEP>".join(sender_copy)
                        f.write(sender_str + "\n")

            if self.senders and phase == Phase.MANUAL_FUZZING:
                logger.info("Start manual app testing")
                self.manual_app_hooking(self.senders, [], [], [])

            if self.senders and len(self.senders) > 0 and phase == Phase.FUZZING:
                starting_time = time.time()

                intermediate_methods_to_hook = self.target_methods_hooker.intermediate_methods_to_hook
                listeners_to_hook = self.target_methods_hooker.listeners
                fragments_to_hook = self.target_methods_hooker.fragments

                """
                intermediate_methods_to_hook = list(self.target_methods_hooker.intermediate_methods_to_hook)
                listeners_to_hook = list(self.target_methods_hooker.listeners)
                fragments_to_hook = list(self.target_methods_hooker.fragments)

                if len(intermediate_methods_to_hook) > 0:
                    self.hooker.instrumenting_app = False
                    intermediate_methods_to_hook = self.verify_hook_on_methods(intermediate_methods_to_hook)
                    time.sleep(2)

                if len(listeners_to_hook) > 0:
                    self.hooker.instrumenting_app = False
                    listeners_to_hook = self.verify_hook_on_methods(listeners_to_hook)
                    time.sleep(2)

                if len(fragments_to_hook) > 0:
                    self.hooker.instrumenting_app = False
                    fragments_to_hook = self.verify_hook_on_methods(fragments_to_hook)
                    self.hooker.instrumenting_app = False
                    self.hooker.terminate()

                logger.debug(f"Hooking {len(self.target_methods_hooker.sink_methods_to_hook)} sender methods")
                logger.debug(f"Hooking {len(intermediate_methods_to_hook)} intermediate methods")
                logger.debug(f"Hooking {len(listeners_to_hook)} listener methods")
                logger.debug(f"Hooking {len(fragments_to_hook)} fragment methods")

                try:
                    self.emulator.terminate()
                except ApkExploded:
                    pass
                """

                logger.info("Start app testing")
                test_app = TestApp(hooker=self.hooker,
                                   firmware_name=self.config["firmware_name"],
                                   firmware_mapping_path=self.config["firmware_mapping"],
                                   timesteps=int(self.layout_config['DEFAULT']['timesteps']),
                                   start_episode=int(self.layout_config['DEFAULT']['start_episode']),
                                   episodes=int(self.layout_config['DEFAULT']['episodes']),
                                   algo=RLAlgorithms(self.layout_config['DEFAULT']['algo']),
                                   appium_port=int(self.layout_config['DEFAULT']['appium_port']),
                                   smartphone_udid=self.device_id,
                                   smartphone_name=self.config["device_name"],
                                   smartphone_apk_path=os.path.abspath(self.config['smartphone_apk_path']),
                                   install_app_from_store=self.config["install_app_from_store"],
                                   reinstall_app=self.reinstall_app,
                                   timer=int(self.layout_config['DEFAULT']['timer']),
                                   max_timesteps=int(self.layout_config['DEFAULT']['max_timesteps']),
                                   pool_strings=os.path.abspath(self.layout_config['DEFAULT']['pool_strings']),
                                   pool_passwords=os.path.abspath(self.layout_config['DEFAULT']['pool_passwords']),
                                   target_methods=self.target_methods_hooker.soot_sink_methods,
                                   app_call_graph=self.target_methods_hooker.cg,
                                   path_to_sinks=self.target_methods_hooker.paths_to_targets,
                                   intermediate_methods_to_hook=set(intermediate_methods_to_hook),
                                   sink_methods_to_hook=self.target_methods_hooker.sink_methods_to_hook,
                                   sniffer=self.sniffer,
                                   bltlog_analyzer=self.bltlog_analyzer,
                                   DELTA=float(self.layout_config['DEFAULT']['delta']),
                                   MAX_REWARD=float(self.layout_config['DEFAULT']['MAX_REWARD']),
                                   app_package_name=self.config['proc_name'],
                                   bad_distance_reward=float(self.layout_config['DEFAULT']['bad_distance_reward']),
                                   good_distance_reward=float(self.layout_config['DEFAULT']['good_distance_reward']),
                                   config_payload_agent=self.config_payload_runtime_path,
                                   output_file_path=self.layout_config['DEFAULT']['output_file_path'],
                                   min_distance_to_sink_rew=False if int(
                                       self.layout_config['DEFAULT']['min_distance_to_sink_rew']) == 0 else True,
                                   sink_reachability_rew=False if int(
                                       self.layout_config['DEFAULT']['sink_reachability_rew']) == 0 else True,
                                   network_monitor_app_package_name=self.config['network_monitor_app'],
                                   new_activity_rew=False if int(
                                       self.layout_config['DEFAULT']['new_activity_rew']) == 0 else True,
                                   reward_activity=float(self.layout_config['DEFAULT']['reward_activity']),
                                   reward_service=float(self.layout_config['DEFAULT']['reward_service']),
                                   reward_broadcast=float(self.layout_config['DEFAULT']['reward_broadcast']),
                                   reward_sink_activity=float(self.layout_config['DEFAULT']['reward_sink_activity']),
                                   reward_sink_service=float(self.layout_config['DEFAULT']['reward_sink_service']),
                                   reward_sink_broadcast=float(self.layout_config['DEFAULT']['reward_sink_broadcast']),
                                   reward_view=float(self.layout_config['DEFAULT']['reward_view']),
                                   reward_sink_reached=float(self.layout_config['DEFAULT']['reward_sink_reached']),
                                   sink_network_rew=False if int(
                                       self.layout_config['DEFAULT']['sink_network_rew']) == 0 else True,
                                   test_dir=self.layout_config['DEFAULT']['test_dir'],
                                   iteration_count=self.layout_config['DEFAULT']['iteration_count'],
                                   sink_activities=self.target_methods_hooker.sink_activities,
                                   sink_services=self.target_methods_hooker.sink_services,
                                   sink_broadcast=self.target_methods_hooker.sink_broadcast,
                                   listeners=set(listeners_to_hook),
                                   fragments=set(fragments_to_hook),
                                   platform_version=self.layout_config['DEFAULT']['android_v'],
                                   iot_device_execution_trace_path=os.path.abspath(
                                       self.layout_config['DEFAULT']['iot_device_execution_trace_path']),
                                   rce_call_log=os.path.abspath(self.layout_config['DEFAULT']['rce_call_log']))
                test_app.test_app()
                logger.info("App layout navigation end")
                elapsed_time = time.time() - starting_time
                eval_stats.write("Time (s): {} app layout navigation end".format(str(elapsed_time)))

            """
            if not self.sp and phase >= Phase.FUZZING_CANDIDATES:
                if not self.lifter:
                    self.create_lifter()
                starting_time = time.time()
                self.phase = Phase.FUZZING_CANDIDATES
                sp = [self.sp_finder.start(s, lifter=self.lifter, ran_fun=replay_ui_async) for s in self.senders]
                self.sp = [x for l in sp for x in l if x]
                elapsed_time = time.time() - starting_time
                eval_stats.write('Time (s): {}\nsweet spots: {}\n'.format(str(elapsed_time), str(self.sp)))
                logger.debug("Sweet spots: {}".format(str(self.sp)))
            """
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())
        finally:
            #self.emulator.terminate()
            os.kill(os.getpid(), signal.SIGKILL)
            sys.exit(0)


if __name__ == "__main__":
    config_path = sys.argv[1]
    phase = Phase.FUZZING
    if len(sys.argv) > 2:
        phase = [value for name, value in vars(Phase).items() if name == sys.argv[2]]
        if not phase:
            print("Invalid phase, options are: " + str([x[6:] for x in list(map(str, Phase))]))
            sys.exit(0)
        phase = phase[0]

    with open(config_path) as fp:
        config = json.load(fp)

    IoTFuzzer(config).run(phase)
