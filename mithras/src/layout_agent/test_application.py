import argparse
import logging
import os
import sys
import traceback
import warnings

warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '6'  # FATAL
logging.getLogger('tensorflow').setLevel(logging.FATAL)
# from algorithms.DDPGExploration import DDPGAlgorithm
from .algorithms.QLearnExploration import QLearnAlgorithm
from .algorithms.SACExploration import SACAlgorithm
from .algorithms.RandomExploration import RandomAlgorithm
from .algorithms.TRPOExploration import TRPOAlgorithm
from .algorithms.RecurrentPPOExploration import RecurrentPPOAlgorithm
from .algorithms.A2CExploration import A2CAlgorithm

import pickle
from .utils.utils import AppiumLauncher, EmulatorLauncher, Utils
from sniffer.sniffer import Sniffer
from sniffer.bltlog_analyzer import BltLogAnalyzer
from frida_hooker.frida_hooker import FridaHooker
from layout_agent.env import LayoutEnv
from selenium.common.exceptions import InvalidSessionIdException, WebDriverException
from networkx import DiGraph
from .utils import apk_analyzer
from loguru import logger
import subprocess
import enum


class RLAlgorithms(enum.Enum):
    Sac = 'SAC'
    Q = 'Q'
    Random = 'random'
    Trpo = 'TRPO'
    RecurrentPPO = 'RecurrentPPO'
    A2C = "A2C"


class EmuType(enum.Enum):
    Normal = 'normal'
    Headless = 'headless'


class PlatformName(enum.Enum):
    Android = 'android'
    iOS = 'iOS'


class TestApp:

    def __init__(self, hooker: FridaHooker, timesteps: int, start_episode: int, episodes: int, algo: RLAlgorithms,
                 appium_port: int, smartphone_udid: str, smartphone_name: str, smartphone_apk_path: str, reinstall_app: bool,
                 firmware_name: str, firmware_mapping_path: str, install_app_from_store: bool, timer: int,
                 max_timesteps: int, pool_strings: str, pool_passwords: str, target_methods: dict, 
                 app_call_graph: DiGraph, path_to_sinks: dict, intermediate_methods_to_hook: set,
                 sink_methods_to_hook: set, app_package_name: str, network_monitor_app_package_name: str,
                 output_file_path: str, test_dir: str, iteration_count: str, sink_reachability_rew: bool,
                 sink_network_rew: bool, min_distance_to_sink_rew: bool, new_activity_rew: bool, DELTA: float,
                 MAX_REWARD: float, reward_sink_reached: float, reward_activity: float, reward_service: float,
                 reward_broadcast: float, reward_sink_activity: float, reward_sink_service: float,
                 reward_sink_broadcast: float, reward_view: float, good_distance_reward: float,
                 config_payload_agent: str, bad_distance_reward: float, sink_activities: set, sink_services: set,
                 sink_broadcast: set, listeners: set, fragments: set, sniffer: Sniffer, bltlog_analyzer: BltLogAnalyzer,
                 iot_device_execution_trace_path: str, rce_call_log: str, platform_name: PlatformName = 'Android',
                 platform_version: str = '9.0', trials_per_app: int = 3, instr_jacoco: bool = False,
                 instr_emma: bool = False, save_policy: bool = True, reload_policy: bool = True,
                 real_device: bool = True, rotation: bool = False, internet: bool = False, menu: bool = False):

        self.start_episode = start_episode
        self.hooker = hooker
        self.smartphone_name = smartphone_name
        self.sink_broadcast = sink_broadcast
        self.sink_services = sink_services
        self.sink_activities = sink_activities
        self.listeners = listeners
        self.fragments = fragments
        self.install_app_from_store = install_app_from_store
        self.reinstall_app = reinstall_app
        self.firmware_name = firmware_name
        self.firmware_mapping_path = firmware_mapping_path
        self.trials_per_app = trials_per_app
        self.bltlog_analyzer = bltlog_analyzer
        self.intermediate_methods_to_hook = intermediate_methods_to_hook
        self.sink_methods_to_hook = sink_methods_to_hook
        self.sink_reachability_rew = sink_reachability_rew
        self.new_activity_rew = new_activity_rew
        self.bad_distance_reward = bad_distance_reward
        self.good_distance_reward = good_distance_reward
        self.config_payload_agent = config_payload_agent
        self.reward_activity = reward_activity
        self.reward_service = reward_service
        self.reward_broadcast = reward_broadcast
        self.reward_sink_activity = reward_sink_activity
        self.reward_sink_service = reward_sink_service
        self.reward_sink_broadcast = reward_sink_broadcast
        self.reward_view = reward_view
        self.reward_sink_reached = reward_sink_reached
        self.MAX_REWARD = MAX_REWARD
        self.DELTA = DELTA
        self.min_distance_to_sink_rew = min_distance_to_sink_rew
        self.test_dir = test_dir
        self.iteration_count = iteration_count
        self.sink_network_rew = sink_network_rew
        self.output_file_path = output_file_path
        self.network_monitor_app_package_name = network_monitor_app_package_name
        self.app_package_name = app_package_name
        self.target_methods = target_methods
        self.path_to_sinks = path_to_sinks
        self.sniffer = sniffer
        self.app_call_graph = app_call_graph
        self.menu = menu
        self.internet = internet
        self.rotation = rotation
        self.real_device = real_device
        self.reload_policy = reload_policy
        self.save_policy = save_policy
        self.instr_emma = instr_emma
        self.instr_jacoco = instr_jacoco
        self.platform_version = platform_version
        self.platform_name = platform_name
        self.pool_strings = pool_strings
        self.pool_passwords = pool_passwords
        self.max_timesteps = max_timesteps
        self.timer = timer
        self.smartphone_apk_path = smartphone_apk_path
        self.smartphone_udid = smartphone_udid
        self.appium_port = appium_port
        self.algo = algo
        self.episodes = episodes
        self.timesteps = timesteps
        self.iot_device_execution_trace_path = iot_device_execution_trace_path
        self.rce_call_log = rce_call_log


    @staticmethod
    def save_pickles(algo, app_name, cycle, button_list, activities, bugs, bug_set):
        os.makedirs(os.path.join(os.getcwd(), 'pickle_files'), exist_ok=True)
        prefix = f'{algo}_{app_name}'
        with open(os.path.join('pickle_files', f'{prefix}_buttons_{cycle}.pkl'), 'wb') as file:
            pickle.dump(button_list, file)

        with open(os.path.join('pickle_files', f'{prefix}_activities_{cycle}.pkl'), 'wb') as file:
            pickle.dump(activities, file)

        with open(os.path.join('pickle_files', f'{prefix}_bugs_{cycle}.pkl'), 'wb') as file:
            pickle.dump(bugs, file)

        with open(os.path.join('pickle_files', f'{prefix}_bug_names_{cycle}.pkl'), 'wb') as file:
            pickle.dump(bug_set, file)

    def test_app(self):
        # Launching appium
        if self.trials_per_app <= 0:
            raise Exception('max_trials must be > 0')
        if self.instr_emma and self.instr_jacoco:
            raise AssertionError

        is_headless = False

        appium = AppiumLauncher(self.appium_port)
        self.emulator = None

        app_name = os.path.basename(os.path.splitext(self.smartphone_apk_path)[0])
        logger.info(f'now testing: {app_name}\n')
        episode = self.start_episode
        count_episode = 1
        trial = 0
        coverage_dict_template = {}
        try:
            app_pkg_play_store, main_activity, exported_activities, services, receivers, providers, string_activities, \
                permissions = apk_analyzer.analyze(self.smartphone_apk_path, coverage_dict_template)
        except Exception as e:
            logger.error(f'{e} at app: {self.smartphone_apk_path}')
            return

        rce_file_count = 0
        while episode < self.episodes:
            logger.info(f'app: {app_name}, test {count_episode} of {self.episodes - self.start_episode} starting')
            # coverage dir
            coverage_dir = ''
            # Creating coverage directory
            if self.instr_emma or self.instr_jacoco:
                coverage_dir = os.path.join(os.getcwd(), 'coverage', app_name, repr(self.algo), str(episode))
                os.makedirs(coverage_dir, exist_ok=True)

            # logs dir
            log_dir_layout = os.path.join(self.test_dir, "layout", self.iteration_count, "logs", repr(self.algo), self.firmware_name, str(episode))
            os.makedirs(log_dir_layout, exist_ok=True)

            log_dir_payload = os.path.join(self.test_dir, "payload", self.iteration_count, "logs", repr(self.algo), self.firmware_name, str(episode))
            os.makedirs(log_dir_payload, exist_ok=True)

            # working dir
            working_dir_layout = os.path.join(self.test_dir, "layout", self.iteration_count, "working_dir", self.firmware_name, self.algo.value)
            os.makedirs(working_dir_layout, exist_ok=True)

            working_dir_payload = os.path.join(self.test_dir, "payload", self.iteration_count, "working_dir", self.firmware_name, self.algo.value)
            os.makedirs(working_dir_payload, exist_ok=True)

            # Creating the policies directory
            policy_dir = os.path.join(os.getcwd(), 'src', 'layout_agent', 'policies')
            os.makedirs(policy_dir, exist_ok=True)

            # instantiating timer in minutes
            coverage_dict = dict(coverage_dict_template)
            widget_list = []
            visited_activities = []
            clicked_buttons = []

            app = None
            try:
                app = LayoutEnv(coverage_dict, smartphone_apk_path=self.smartphone_apk_path,
                                       firmware_name=self.firmware_name,
                                       firmware_mapping_path=self.firmware_mapping_path,
                                       smartwatch_apk_path="",
                                       install_app_from_store=self.install_app_from_store,
                                       reinstall_app=self.reinstall_app,
                                       list_activities=list(coverage_dict.keys()),
                                       widget_list=widget_list,
                                       coverage_dir=coverage_dir,
                                       working_dir_layout=working_dir_layout,
                                       log_dir_layout=log_dir_layout,
                                       working_dir_payload=working_dir_payload,
                                       log_dir_payload=log_dir_payload,
                                       visited_activities=visited_activities,
                                       clicked_buttons=clicked_buttons,
                                       string_activities=string_activities,
                                       appium_port=self.appium_port,
                                       internet=self.internet,
                                       instr_emma=self.instr_emma,
                                       instr_jacoco=self.instr_jacoco,
                                       button_menu=self.menu,
                                       rotation=self.rotation,
                                       platform_name=self.platform_name,
                                       platform_version=self.platform_version,
                                       smartphone_udid=self.smartphone_udid,
                                       smartwatch_udid="",
                                       pool_strings=self.pool_strings,
                                       pool_passwords=self.pool_passwords,
                                       hooker=self.hooker,
                                       device_name=self.smartphone_name,
                                       max_episode_len=self.max_timesteps,
                                       is_headless=is_headless, appium=appium, emulator=self.emulator,
                                       package=app_pkg_play_store, main_activity=main_activity,
                                       exported_activities=exported_activities,
                                       services=services, receivers=receivers, permissions=set(permissions),
                                       target_methods=self.target_methods,
                                       app_call_graph=self.app_call_graph,
                                       intermediate_methods_to_hook=self.intermediate_methods_to_hook,
                                       sink_methods_to_hook=self.sink_methods_to_hook,
                                       sink_activities=self.sink_activities,
                                       sink_services=self.sink_services,
                                       sink_broadcast=self.sink_broadcast,
                                       listeners=self.listeners,
                                       fragments=self.fragments,
                                       paths_to_sinks=self.path_to_sinks,
                                       sniffer=self.sniffer,
                                       MAX_REWARD=self.MAX_REWARD,
                                       reward_sink_reached=self.reward_sink_reached,
                                       reward_activity=self.reward_activity,
                                       reward_service=self.reward_service,
                                       reward_broadcast=self.reward_broadcast,
                                       reward_sink_activity=self.reward_sink_activity,
                                       reward_sink_service=self.reward_sink_service,
                                       iteration_count=self.iteration_count,
                                       reward_sink_broadcast=self.reward_sink_broadcast,
                                       reward_view=self.reward_view,
                                       good_distance_reward=self.good_distance_reward,
                                       config_payload_agent=self.config_payload_agent,
                                       bad_distance_reward=self.bad_distance_reward,
                                       bltlog_analyzer=self.bltlog_analyzer,
                                       DELTA=self.DELTA,
                                       episode=episode,
                                       output_file_path=self.output_file_path,
                                       min_distance_to_sink_rew=self.min_distance_to_sink_rew,
                                       network_monitor_app_package_name=self.network_monitor_app_package_name,
                                       sink_network_rew=self.sink_network_rew,
                                       new_activity_rew=self.new_activity_rew,
                                       sink_reachability_rew=self.sink_reachability_rew,
                                       iot_device_execution_trace_path=self.iot_device_execution_trace_path,
                                       rce_call_log=self.rce_call_log,
                                       rce_file_count=rce_file_count)
                if self.algo == RLAlgorithms.Random:
                    algorithm = RandomAlgorithm()
                elif self.algo == RLAlgorithms.Sac:
                    algorithm = SACAlgorithm()
                elif self.algo == RLAlgorithms.Q:
                    algorithm = QLearnAlgorithm()
                elif self.algo == RLAlgorithms.A2C:
                    algorithm = A2CAlgorithm()
                elif self.algo == RLAlgorithms.RecurrentPPO:
                    algorithm = RecurrentPPOAlgorithm()
                elif self.algo == RLAlgorithms.Trpo:
                    algorithm = TRPOAlgorithm()
                else:
                    logger.error(f"Algorithm {repr(self.algo)} does not exist")
                    sys.exit(1)

                if self.start_episode == 0 and episode == 0 and os.path.exists(
                        policy_dir + os.sep + app_pkg_play_store):
                    os.remove(policy_dir + os.sep + app_pkg_play_store)

                logger.info("Start RL algorithm")
                flag = algorithm.explore(app, self.emulator, appium, self.timesteps, self.timer,
                                         save_policy=self.save_policy,
                                         reload_policy=self.reload_policy, app_name=app_name,
                                         policy_dir=policy_dir,
                                         cycle=episode)
                rce_file_count = app.rce_file_count
                app.write_test_logs(f"NUM TIMESTEPS: {app.timesteps}<EPISODE>{episode}")
                if flag:
                    with open(f'{log_dir_layout}{os.sep}success.log', 'a+') as f:
                        f.write(f'{app_name}\n')
                else:
                    with open(f'{log_dir_layout}{os.sep}error.log', 'a+') as f:
                        f.write(f'{app_name}\n')
            except Exception:
                logger.error(traceback.format_exc())
                flag = False
                rce_file_count = app.rce_file_count

            if flag:
                try:
                    app.reset()
                    app.driver.quit()
                except InvalidSessionIdException:
                    logger.error("Quit Appium Server: InvalidSessionIdException")
                except WebDriverException:
                    logger.error("Quit Appium Server: WebDriverException")
                logger.remove(app.logger_id)
                # save_pickles(algo, app_name, episode, clicked_buttons, visited_activities, number_bugs, bug_set)
                logger.info(f'app: {app_name}, test {count_episode} of {self.episodes - self.start_episode} ending\n')
                episode += 1
                count_episode += 1
            else:
                trial += 1
                logger.debug(f"Trial number: {trial}")
                if trial == self.trials_per_app:
                    if app.driver:
                        try:
                            app.driver.quit()
                        except Exception:
                            logger.error(traceback.format_exc())
                            logger.error("Quit Appium Server: Quit")
                    logger.error(f'Too Many Times tried, app: {app_name}, iteration: {episode}')
                    break
        if self.emulator is not None:
            self.emulator.terminate()
        return 0
