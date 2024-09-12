import enum
import re
import shutil
import subprocess
import sys
import traceback

from loguru import logger
from run import Phase
from configparser import ConfigParser
import argparse
import json
import os


class FuzzerTimeOutException(Exception):
    pass


class LaunchModes(enum.Enum):
    static = "static"
    test = "test"

    def __str__(self):
        return self.name

    @staticmethod
    def from_string(s):
        try:
            return LaunchModes[s]
        except KeyError:
            raise ValueError()


def delete_invalid_runs(logs_folder: str, algorithm: str, app: str, config_ares: ConfigParser):
    if os.path.exists(logs_folder + os.sep + app):
        for algo_log in os.listdir(logs_folder + os.sep + app):
            if algorithm in algo_log:
                algo_logs_folder = logs_folder + os.sep + app + os.sep + algo_log
                last_valid_episode = None
                episode_app_folders = os.listdir(algo_logs_folder)
                for episode_log in range(len(episode_app_folders)):
                    episode_log_folder = algo_logs_folder + os.sep + episode_app_folders[episode_log]
                    if not os.path.exists(episode_log_folder + os.sep + "success.log"):
                        if not last_valid_episode and episode_log > 0:
                            last_valid_episode = episode_app_folders[episode_log - 1]
                        shutil.rmtree(episode_log_folder)
                        app_working_dir = f"src{os.sep}layout_agent{os.sep}working_dir{os.sep}" \
                                          f"{config_ares['DEFAULT']['iteration_count']}{os.sep}" \
                                          f"{algorithm}{os.sep}{app}"

                        for log_file in os.listdir(app_working_dir):
                            modify_file = False
                            with open(app_working_dir + os.sep + log_file, "r") as f:
                                lines = f.readlines()
                                lines_to_delete_idx = []
                                for i in range(len(lines)):
                                    if re.search(f"<EPISODE>{episode_app_folders[episode_log]}</EPISODE>", lines[i]):
                                        modify_file = True
                                        lines_to_delete_idx.append(i)
                                    else:
                                        break

                                for idx in lines_to_delete_idx:
                                    del lines[idx]

                            if modify_file:
                                with open(app_working_dir + os.sep + log_file, "w") as f:
                                    f.writelines(lines)

                episode_app_folders = os.listdir(algo_logs_folder)
                if len(episode_app_folders) == 0:
                    shutil.rmtree(algo_logs_folder)
                    return

                if last_valid_episode:
                    episode_app_folders = os.listdir(algo_logs_folder)
                    for episode_log in range(len(episode_app_folders)):
                        if int(episode_app_folders[episode_log]) == last_valid_episode:
                            for episode_to_rename in range(int(episode_app_folders[episode_log]) + 1,
                                                           int(episode_app_folders[-1]) + 1):
                                os.rename(f"{algo_logs_folder}{os.sep}{episode_app_folders[episode_to_rename]}",
                                          f"{algo_logs_folder}{os.sep}{int(episode_app_folders[episode_to_rename - 1]) + 1}")
                                episode_app_folders[episode_to_rename] = str(int(episode_app_folders[episode_to_rename - 1]) + 1)
                            break


def main(mode: LaunchModes, app_folder: str, config_app_iterations_path: str, config_path: str, config_ares_path: str,
         test_dir: str,
         algorithm: str):
    if not os.path.exists(config_path):
        logger.error("The config file does not exist")
        return

    if not os.path.exists(config_ares_path):
        logger.error("The config layout_agent file does not exist")
        return

    if not os.path.exists(app_folder):
        logger.error("The app folder path does not exist")
        return

    phase = [value for name, value in vars(Phase).items() if name == "FUZZING"]
    if not phase:
        logger.error("Invalid phase, options are: " + str([x[6:] for x in list(map(str, Phase))]))
        return

    with open(config_app_iterations_path, "r") as f:
        config_app_iterations = json.load(f)
        for app in config_app_iterations:
            config_app_iterations[app] = config_app_iterations[app][algorithm]

    if mode == LaunchModes.static:
        for app in config_app_iterations:
            pickle_apk_soot = os.path.abspath(os.path.dirname(__file__)) + os.sep + "pickle_apk_soot" + os.sep + app
            pickle_cfg_soot = os.path.abspath(os.path.dirname(__file__)) + os.sep + "pickle_cfg_soot" + os.sep + app
            if not os.path.exists(pickle_apk_soot) or not os.path.exists(pickle_cfg_soot):
                with open(config_path, "r") as f:
                    config_json = json.load(f)

                config_json['smartphone_apk_path'] = os.path.abspath(app_folder + os.sep + "smartphone_apps" + os.sep +
                                                                     app + ".apk")
                config_json['smartwatch_apk_path'] = os.path.abspath(app_folder + os.sep + "smartwatch_apps" + os.sep +
                                                                     app + ".apk")
                config_json['proc_name'] = app

                with open(config_path, "w") as f:
                    json.dump(config_json, f)
                try:
                    subprocess.call([sys.executable, "run.py", config_path, "MESSAGE_SENDER"])
                except:
                    logger.error(f"Error analyzing app: {app}")
                    logger.error(traceback.format_exc())

    elif mode == LaunchModes.test:
        while True:
            iteration_lens_list = [len(config_app_iterations[app]) for app in config_app_iterations]
            test_list = [True if num_iterations == 0 else False for num_iterations in iteration_lens_list]
            if all(test_list):
                break

            for app in config_app_iterations:
                if len(config_app_iterations[app]) != 0:
                    logs_folder_it = test_dir + os.sep + str(config_app_iterations[app][0]) + os.sep + "logs"
                    if os.path.exists(logs_folder_it):
                        for elem in os.listdir(logs_folder_it):
                            if os.path.isdir(logs_folder_it + os.sep + elem) and algorithm in elem:
                                logs_folder_it = logs_folder_it + os.sep + elem
                                break

                    with open(config_path, "r") as f:
                        config_json = json.load(f)

                    with open(config_ares_path, "r") as f:
                        config_ares = ConfigParser()
                        config_ares.read_file(f)

                    num_episodes_original = int(config_ares['DEFAULT']['episodes'])
                    start_episode = 0
                    execute_rl = True
                    if os.path.exists(logs_folder_it + os.sep + app):
                        episode_logs = os.listdir(logs_folder_it + os.sep + app)
                        if len(episode_logs) == num_episodes_original:
                            execute_rl = False

                        if len(episode_logs) < num_episodes_original:
                            start_episode = len(episode_logs)

                    if execute_rl:
                        with open(os.path.dirname(config_ares_path) + os.sep + "config.ini", "w+") as f:
                            config_ares['DEFAULT']['algo'] = algorithm
                            config_ares['DEFAULT']['start_episode'] = str(start_episode)
                            config_ares['DEFAULT']['iteration_count'] = str(config_app_iterations[app][0])
                            config_ares.write(f)

                        logger.info(f"Analyzing app: {app} - Algorithm: {algorithm}")
                        config_json['smartphone_apk_path'] = os.path.abspath(app_folder + os.sep + "smartphone_apps" +
                                                                             os.sep + app + ".apk")
                        config_json['smartwatch_apk_path'] = os.path.abspath(app_folder + os.sep + "smartwatch_apps" +
                                                                             os.sep + app + ".apk")
                        config_json['proc_name'] = app

                        with open(config_path, "w") as f:
                            json.dump(config_json, f)

                        try:
                            delete_invalid_runs(logs_folder_it, algorithm, app, config_ares)
                            subprocess.call([sys.executable, "run.py", config_path, "FUZZING"])
                        except:
                            logger.error(f"Error analyzing app: {app}")
                            logger.error(traceback.format_exc())
                        finally:
                            delete_invalid_runs(logs_folder_it, algorithm, app, config_ares)
                            break
                    else:
                        del config_app_iterations[app][0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-mode", type=LaunchModes.from_string, choices=list(LaunchModes), default="test")
    parser.add_argument("-apps", type=str, default="/home/kali/Documents/git/Mithras/mithras/apps")
    parser.add_argument("-cf", type=str, default="/home/kali/Documents/git/Mithras/mithras/config.json")
    parser.add_argument("-cf_ares_iterations", type=str, default="/home/kali/Documents/git/Mithras/mithras"
                                                                 "/config_app_iterations.json")
    parser.add_argument("-cf_ares", type=str, default="/home/kali/Documents/git/Mithras/mithras/src/layout_agent/config_default"
                                                      ".ini")
    parser.add_argument("-test_dir", type=str, default="/home/kali/Documents/git/Mithras/mithras/src/layout_agent/tests")
    parser.add_argument("-algos", type=str, nargs="*", default="TRPO")
    args = parser.parse_args()

    for algo in args.algos:
        main(args.mode, args.apps, args.cf_ares_iterations, args.cf, args.cf_ares, args.test_dir, algo)
