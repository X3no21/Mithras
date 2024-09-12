import os
import shutil
import subprocess

from loguru import logger
import configparser
import signal
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


class AppiumLauncher:

    def __init__(self, port: int):
        self.port: int = port
        self.adb_path: str = Utils.get_adb_executable_path()

    def terminate(self):
        lsof_proc = subprocess.Popen(["lsof", "-t", f"-i:{self.port}"], stdout=subprocess.PIPE)
        out, _ = lsof_proc.communicate()
        pid_list = out.decode()
        for pid in pid_list.split('\n'):
            pid = pid.strip()
            if pid.isnumeric():
                logger.info("Stopping Appium Server")
                os.kill(int(pid), signal.SIGKILL)
        time.sleep(1.0)

    def start_appium(self):
        try:
            logger.info("Starting Appium service")
            subprocess.Popen(["appium", "-p", str(self.port)], stdout=open("/dev/null", "w"))
            os.system(f"{self.adb_path} start-server")
            time.sleep(3.0)
        except:
            pass
        logger.info("Appium service started")

    def restart_appium(self):
        self.terminate()
        self.start_appium()


class EmulatorLauncher:
    def __init__(self, emu, smartphone_name, smartphone_port, smartphone_snapshot_name,
                 smartwatch_name, smartwatch_port, smartwatch_snapshot_name):
        self.smartphone_name: str = '@' + smartphone_name.replace(' ', '_')
        self.smartphone_name_original = smartphone_name + ".avd"
        self.smartwatch_name: str = '@' + smartwatch_name.replace(' ', '_')
        self.smartwatch_name_original = smartwatch_name + ".avd"
        self.emu: str = emu
        self.smartphone_port: int = smartphone_port
        self.smartwatch_port: int = smartwatch_port
        self.smartphone_snapshot_name = smartphone_snapshot_name
        self.smartwatch_snapshot_name = smartwatch_snapshot_name
        self.adb_path: str = Utils.get_adb_executable_path()
        self.emulator_path: str = Utils.get_emulator_executable_path()

    def terminate(self):
        logger.info("Stopping Android Emulators")
        lsof_proc = subprocess.Popen(["lsof", "-t", f"-i:{self.smartphone_port}"], stdout=subprocess.PIPE)
        out, _ = lsof_proc.communicate()
        pid_smartphone_list = out.decode()

        lsof_proc = subprocess.Popen(["lsof", "-t", f"-i:{self.smartwatch_port}"], stdout=subprocess.PIPE)
        out, _ = lsof_proc.communicate()
        pid_smartwatch_list = out.decode()

        for pid_smartphone in pid_smartphone_list.split('\n'):
            pid_smartphone = pid_smartphone.strip()
            if pid_smartphone.isnumeric():
                os.kill(int(pid_smartphone), signal.SIGKILL)

        for pid_smartwatch in pid_smartwatch_list.split('\n'):
            pid_smartwatch = pid_smartwatch.strip()
            if pid_smartwatch:
                os.kill(int(pid_smartwatch), signal.SIGKILL)
        time.sleep(5.0)

        emu_path = os.path.expanduser('~') + os.sep + ".android" + os.sep + "avd"
        subprocess.call(["rm", "-rf", emu_path + os.sep + self.smartphone_name_original + os.sep + "*.lock"])
        subprocess.call(["rm", "-rf", emu_path + os.sep + self.smartwatch_name_original + os.sep + "*.lock"])

    def start_emulator(self):
        adb_devices_proc = subprocess.Popen(["adb", "devices"], stdout=subprocess.PIPE)
        out_command = adb_devices_proc.stdout.read().decode()

        lsof_proc = subprocess.Popen(["lsof", "-t", f"-i:{self.smartphone_port}"], stdout=subprocess.PIPE)
        out, _ = lsof_proc.communicate()
        pid_smartphone = out.decode().strip()

        lsof_proc = subprocess.Popen(["lsof", "-t", f"-i:{self.smartwatch_port}"], stdout=subprocess.PIPE)
        out, _ = lsof_proc.communicate()
        pid_smartwatch = out.decode().strip()

        if pid_smartphone.isnumeric() and pid_smartwatch.isnumeric():
            logger.info("Emulators already started")
            return

        if str(self.smartphone_port) in out_command and str(self.smartwatch_port) in out_command:
            logger.info("Emulators already started")
            return

        logger.info("Starting Android Emulators")
        if self.emu == 'normal':
            subprocess.Popen([self.emulator_path, self.smartphone_name,
                              '-port', str(self.smartphone_port),
                              '-snapshot',
                              self.smartphone_snapshot_name], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

            """
            subprocess.Popen([self.emulator_path, self.smartwatch_name,
                              '-port', str(self.smartwatch_port),
                              '-snapshot',
                              self.smartwatch_snapshot_name], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
            """
            time.sleep(40.0)
        else:
            # Headless emulator.
            subprocess.Popen([self.emulator_path, self.smartphone_name,
                              '-port', str(self.smartphone_port),
                              '-no-window',
                              '-no-snapshot', '-no-audio',
                              '-no-boot-anim',
                              '-snapshot',
                              self.smartphone_snapshot_name], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

            """
            subprocess.Popen([self.emulator_path, self.smartwatch_name,
                              '-port', str(self.smartwatch_port),
                              '-no-window',
                              '-no-snapshot', '-no-audio',
                              '-no-boot-anim',
                              '-snapshot',
                              self.smartwatch_snapshot_name], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
            """
            time.sleep(40.0)

        """
        os.system(
            f'{self.adb_path} -s emulator-{self.smartphone_port} shell settings put global window_animation_scale 0')
        os.system(
            f'{self.adb_path} -s emulator-{self.smartphone_port} shell settings put global transition_animation_scale 0')
        os.system(
            f'{self.adb_path} -s emulator-{self.smartphone_port} shell settings put global animator_duration_scale 0')
        logger.info("Android Emulator Started")
        """

    def restart_emulator(self):
        self.terminate()
        self.start_emulator()


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
