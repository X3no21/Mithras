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


def main(app_folder: str, config_path: str, config_ares_path: str, logs_folder: str, algorithm: str):
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
    phase = phase[0]

    test_app_completed = dict()
    for app in os.listdir(app_folder):
        if app.endswith(".apk"):
            test_app_completed[app] = False

    while not all(test_app_completed.values()):
        for app in os.listdir(app_folder):
            if app.endswith(".apk"):
                with open(config_path, "r") as f:
                    config_json = json.load(f)

                with open(config_ares_path, "r") as f:
                    config_ares = ConfigParser()
                    config_ares.read_file(f)

                num_episodes_original = int(config_ares['DEFAULT']['episodes'])
                start_episode = 0
                execute_rl = True
                if os.path.exists(logs_folder + os.sep + app[:-4]):
                    algos_logs = os.listdir(logs_folder + os.sep + app[:-4])
                    for algo_log in algos_logs:
                        if algorithm in algo_log:
                            algo_logs_folder = logs_folder + os.sep + app[:-4] + os.sep + algo_log
                            episode_logs = os.listdir(algo_logs_folder)
                            if len(episode_logs) == num_episodes_original:
                                execute_rl = False

                            if len(episode_logs) < num_episodes_original:
                                start_episode = len(episode_logs)
                            break

                if execute_rl:
                    with open(os.path.dirname(config_ares_path) + os.sep + "config.ini", "w+") as f:
                        config_ares['DEFAULT']['algo'] = algorithm
                        config_ares['DEFAULT']['start_episode'] = str(start_episode)
                        config_ares.write(f)

                    logger.info(f"Analyzing app: {app} - Algorithm: {algorithm}")
                    config_json['apk_path'] = os.path.abspath(app_folder + os.sep + app)
                    config_json['proc_name'] = app[:-4]

                    with open(config_path, "w") as f:
                        json.dump(config_json, f)

                    try:
                        subprocess.call([sys.executable, "run.py", config_path, "FUZZING"])
                    except:
                        logger.error(f"Error analyzing app: {app}")
                        logger.error(traceback.format_exc())
                    finally:
                        if os.path.exists(logs_folder + os.sep + app[:-4]):
                            algos_logs = os.listdir(logs_folder + os.sep + app[:-4])
                            for algo_log in algos_logs:
                                if algorithm in algo_log:
                                    algo_logs_folder = logs_folder + os.sep + app[:-4] + os.sep + algo_log
                                    episode_logs = os.listdir(algo_logs_folder)
                                    if len(episode_logs) > 0:
                                        last_episode_folder = algo_logs_folder + os.sep + str(len(episode_logs) - 1)
                                        if not os.path.exists(last_episode_folder + os.sep + "success.log"):
                                            shutil.rmtree(last_episode_folder)
                                            app_working_dir = f"src{os.sep}layout_agent{os.sep}working_dir{os.sep}{algorithm}" \
                                                              f"{os.sep}{app[:-4]}"
                                            for log_file in os.listdir(app_working_dir):
                                                modify_file = False
                                                with open(app_working_dir + os.sep + log_file, "r") as f:
                                                    lines = f.readlines()
                                                    lines_to_delete_idx = []
                                                    for i in range(len(lines)):
                                                        idx = (len(lines) - 1) - i
                                                        if re.search(f"<EPISODE>{len(episode_logs) - 1}</EPISODE>",
                                                                     lines[idx]):
                                                            modify_file = True
                                                            lines_to_delete_idx.append(idx)
                                                        else:
                                                            break

                                                    for _ in lines_to_delete_idx:
                                                        lines.pop(-1)

                                                if modify_file:
                                                    with open(app_working_dir + os.sep + log_file, "w") as f:
                                                        f.writelines(lines)

                                    break
                else:
                    test_app_completed[app] = True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-apps", type=str, default="/home/kali/Documents/git/Mithras/mithras/apps")
    parser.add_argument("-cf", type=str, default="/home/kali/Documents/git/Mithras/mithras/config.json")
    parser.add_argument("-cf_ares", type=str,
                        default="/home/kali/Documents/git/Mithras/mithras/src/layout_agent/config_default.ini")
    parser.add_argument("-logs_folder", type=str, default="/home/kali/Documents/git/Mithras/mithras/src/layout_agent/logs")
    parser.add_argument("-algos", type=str, nargs="*", default="random")
    args = parser.parse_args()

    for algo in args.algos:
        main(args.apps, args.cf, args.cf_ares, args.logs_folder, algo)
