import os
import shutil
import subprocess

from loguru import logger
import configparser
import psutil
import signal
import enum
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


class EmulationEngine(enum.Enum):
    FIRMADYNE = "firmadyne"
    FIRMAE = "firmae"
    DEFAULT = "default"

    @classmethod
    def from_string(cls, value: str):
        return cls.__members__.get(value.upper(), cls.DEFAULT)


class EmulatorLauncher:
    def __init__(self, root_passowrd, smartphone_emu_type, iot_device_emu_engine, firmware_path, firmware_vendor,
                 smartphone_name, smartphone_port, smartphone_snapshot_name=None):
        self.root_password = root_passowrd
        self.firmware_path = firmware_path
        self.firmware_vendor = firmware_vendor
        self.smartphone_name: str = '@' + smartphone_name.replace(' ', '_')
        self.smartphone_name_original = smartphone_name + ".avd"
        self.smartphone_emu_type: str = smartphone_emu_type
        self.iot_device_emu_engine: EmulationEngine = iot_device_emu_engine
        self.smartphone_port: int = smartphone_port
        self.smartphone_snapshot_name = smartphone_snapshot_name
        self.firmae_path = None
        self.adb_path: str = Utils.get_adb_executable_path()
        self.emulator_path: str = Utils.get_emulator_executable_path()

        self.iot_emulated_firmwares_dir = ""
        if self.iot_device_emu_engine == EmulationEngine.FIRMADYNE:
            firmadyne_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))),
                "firmware-analysis-toolkit")
            self.iot_emulated_firmwares_dir = f"{firmadyne_path}{os.sep}firmadyne{os.sep}scratch"
            emulated_firmware_dirs = []
            for emu_dir in os.listdir(self.iot_emulated_firmwares_dir):
                if emu_dir.isnumeric():
                    emulated_firmware_dirs.append(int(emu_dir))
            self.emulated_firmware_dir = max(emulated_firmware_dirs)
        else:
            self.firmae_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))), "FirmAE")

    def is_frida_binary_present(self):
        try:
            result = subprocess.run(
                [self.adb_path, "-s", f"emulator-{self.smartphone_port}", "shell", "ls /data/local/tmp/frida-server"],
                capture_output=True, text=True)
            if 'No such file or directory' in result.stderr:
                return False
            else:
                return True
        except subprocess.CalledProcessError as e:
            print(f"Error checking Frida server binary: {e}")
            return False

    def push_frida_binary(self):
        try:
            local_frida_server_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "bin", "frida-server")
            remote_frida_server_path = "/data/local/tmp/frida-server"
            if os.path.exists(local_frida_server_path):
                subprocess.run([self.adb_path, "-s", f"emulator-{self.smartphone_port}", "push", local_frida_server_path,
                                remote_frida_server_path], check=True)
                subprocess.run([self.adb_path, "-s", f"emulator-{self.smartphone_port}", "shell",
                                f"chmod 755 {remote_frida_server_path}"], check=True)
            else:
                print(f"Frida server binary not found at local path: {local_frida_server_path}")
        except subprocess.CalledProcessError as e:
            print(f"Error pushing Frida server binary: {e}")

    def is_frida_running(self):
        try:
            result = subprocess.run([self.adb_path, "-s", f"emulator-{self.smartphone_port}", "shell", "ps | grep frida-server"],
                capture_output=True, text=True)
            if 'frida-server' in result.stdout:
                return True
            else:
                return False
        except subprocess.CalledProcessError as e:
            print(f"Error checking Frida server status: {e}")
            return False

    def start_frida_server(self):
        try:
            subprocess.Popen([self.adb_path, "-s", f"emulator-{self.smartphone_port}", "shell", "/data/local/tmp/frida-server &"])
            time.sleep(1)
        except subprocess.CalledProcessError as e:
            print(f"Error starting Frida server: {e}")

    def terminate(self):
        logger.info("Stopping Android Emulator")
        lsof_proc = subprocess.Popen(["lsof", "-t", f"-i:{self.smartphone_port}"], stdout=subprocess.PIPE)
        out, _ = lsof_proc.communicate()
        pid_smartphone_list = out.decode()

        for pid_smartphone in pid_smartphone_list.split('\n'):
            pid_smartphone = pid_smartphone.strip()
            if pid_smartphone.isnumeric():
                os.kill(int(pid_smartphone), signal.SIGKILL)
        time.sleep(5.0)

        emu_path = os.path.expanduser('~') + os.sep + ".android" + os.sep + "avd"
        subprocess.call(["rm", "-rf", emu_path + os.sep + self.smartphone_name_original + os.sep + "*.lock"])

        for process in psutil.process_iter(attrs=['pid', 'name']):
            try:
                if 'qemu' in process.info['name'].lower():
                    print(f"Killing process {process.info['name']} with PID {process.info['pid']}")
                    os.kill(process.info['pid'], signal.SIGKILL)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def start_emulator(self):
        adb_devices_proc = subprocess.Popen([self.adb_path, "devices"], stdout=subprocess.PIPE)
        out_command = adb_devices_proc.stdout.read().decode()

        lsof_proc = subprocess.Popen(["lsof", "-t", f"-i:{self.smartphone_port}"], stdout=subprocess.PIPE)
        out, _ = lsof_proc.communicate()
        pid_smartphone = out.decode().strip()

        if pid_smartphone.isnumeric():
            logger.info("Emulator already started")
            return

        if str(self.smartphone_port) in out_command:
            logger.info("Emulator already started")
            return

        logger.info("Starting Android Emulator")
        if self.smartphone_emu_type == 'normal':
            if self.smartphone_snapshot_name:
                subprocess.Popen([self.emulator_path, self.smartphone_name,
                                  '-port', str(self.smartphone_port),
                                  '-snapshot',
                                  self.smartphone_snapshot_name], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            else:
                subprocess.Popen([self.emulator_path, self.smartphone_name,
                                  '-port', str(self.smartphone_port)], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        else:
            # Headless emulator.
            if self.smartphone_snapshot_name:
                subprocess.Popen([self.emulator_path, self.smartphone_name,
                                  '-port', str(self.smartphone_port),
                                  '-no-window',
                                  '-no-snapshot', '-no-audio',
                                  '-no-boot-anim',
                                  '-snapshot',
                                  self.smartphone_snapshot_name], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            else:
                subprocess.Popen([self.emulator_path, self.smartphone_name,
                                  '-port', str(self.smartphone_port),
                                  '-no-window',
                                  '-no-snapshot', '-no-audio',
                                  '-no-boot-anim'], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)

        if self.iot_device_emu_engine == EmulationEngine.FIRMADYNE:
            p = subprocess.Popen(
                ["sudo", "-S", f"{self.iot_emulated_firmwares_dir}{os.sep}{self.emulated_firmware_dir}{os.sep}run.sh"],
                stdout=subprocess.DEVNULL, stdin=subprocess.PIPE)
            p.stdin.write(f"{self.root_password}\n".encode())
            p.stdin.close()
        else:
            cwd = os.getcwd()
            os.chdir(self.firmae_path)
            p = subprocess.Popen(["sudo", "-S", "./run.sh", "-r", self.firmware_vendor, self.firmware_path],
                                 stdout=subprocess.DEVNULL,
                                 stdin=subprocess.PIPE)
            p.stdin.write(f"{self.root_password}\n".encode())
            p.stdin.close()
            os.chdir(cwd)
        time.sleep(60.0)

        os.system(
            f'{self.adb_path} -s emulator-{self.smartphone_port} shell settings put global window_animation_scale 0')
        os.system(
            f'{self.adb_path} -s emulator-{self.smartphone_port} shell settings put global transition_animation_scale 0')
        os.system(
            f'{self.adb_path} -s emulator-{self.smartphone_port} shell settings put global animator_duration_scale 0')

        if not self.is_frida_binary_present():
            self.push_frida_binary()

        if not self.is_frida_running():
            self.start_frida_server()

        logger.info("Android Emulator Started")

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
