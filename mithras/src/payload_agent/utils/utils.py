import os
import shutil

import configparser
import time

config = configparser.ConfigParser()
config.read(os.path.abspath(os.path.dirname(os.path.dirname(__file__))) + os.sep + "config.ini")


class Utils:

    @staticmethod
    def get_adb_executable_path() -> str:
        adb_path = shutil.which(
            "adb", path=os.path.join(config["DEFAULT"]["android_home"], "platform-tools")
        )
        if not adb_path or not os.path.isfile(adb_path):
            raise FileNotFoundError(
                "Adb (Android Debug Bridge) executable is not available! "
                "Please check your Android SDK installation."
            )
        return adb_path

    @staticmethod
    def get_appium_executable_path() -> str:
        appium_path = shutil.which("appium")
        if not appium_path or not os.path.isfile(appium_path):
            raise FileNotFoundError(
                "Appium executable is not available! "
                "Please check your Appium installation."
            )
        return appium_path

    @staticmethod
    def get_emulator_executable_path() -> str:
        emulator_path = shutil.which(
            "emulator", path=os.path.join(os.environ.get("ANDROID_HOME"), "emulator")
        )
        if not emulator_path or not os.path.isfile(emulator_path):
            raise FileNotFoundError(
                "Emulator executable is not available! "
                "Please check your Android SDK installation."
            )
        return emulator_path

    @staticmethod
    def compute_coverage(coverage_dict):
        visited_activities = 0
        pressed_buttons = 0
        for key in coverage_dict.keys():
            for small_key in coverage_dict[key].keys():
                if small_key == 'visited':
                    if coverage_dict[key][small_key]:
                        visited_activities += 1
                else:
                    if coverage_dict[key][small_key]:
                        pressed_buttons += 1
        return visited_activities, pressed_buttons


class Timer:

    # timer expressed in minutes
    def __init__(self, timer=30):
        self.start = time.perf_counter()
        self.timer = timer

    def time_elapsed_seconds(self):
        return time.perf_counter() - self.start

    def time_elapsed_minutes(self):
        return int((time.perf_counter() - self.start) / 60.0)

    def timer_expired(self):
        return True if (int((time.perf_counter() - self.start) / 60.0) >= self.timer) else False
