import os
import subprocess
import json
import enum
import sys


class EmulationEngine(enum.Enum):
    FIRMADYNE = "firmadyne"
    FIRMAE = "firmae"
    DEFAULT = "default"

    @classmethod
    def from_string(cls, value: str):
        return cls.__members__.get(value.upper(), cls.DEFAULT)


with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), "instrumentation_pipeline.json"), "r") as f:
    config_script = json.load(f)

firmadyne_path = os.path.join(os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))), "firmware-analysis-toolkit")
firmae_path = os.path.join(os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))), "FirmAE")
firmware_name = config_script["firmware_name"]
root_password = config_script["root_password"]
emulation_engine = EmulationEngine.from_string(config_script["emulation_engine"])

if emulation_engine == EmulationEngine.DEFAULT:
    print("Emulation engine not valid")
    sys.exit(1)


def backup_folder(folder):
    dst_bck = f"{folder}.bck"
    if os.path.exists(dst_bck):
        return
    p = subprocess.Popen(["sudo", "-S", "cp", "-r", folder, dst_bck], stdin=subprocess.PIPE)
    p.communicate(f'{root_password}\n'.encode())
    print(f"Folder {folder} copied to {dst_bck}")


def mount_raw_file(image_raw_path, mount_point):
    if not os.path.exists(mount_point):
        os.makedirs(mount_point)

    p = subprocess.Popen(['sudo', '-S', 'modprobe', 'nbd'], stdin=subprocess.PIPE)
    p.communicate(f'{root_password}\n'.encode())

    p = subprocess.Popen(['sudo', '-S', 'qemu-nbd', '--format=raw', '-c', '/dev/nbd0', image_raw_path], stdin=subprocess.PIPE)
    p.communicate(f'{root_password}\n'.encode())

    p = subprocess.Popen(['sudo', '-S', 'mkdir', '-p', mount_point], stdin=subprocess.PIPE)
    p.communicate(f'{root_password}\n'.encode())

    p = subprocess.Popen(['sudo', '-S', 'mount', '/dev/nbd0p1', mount_point], stdin=subprocess.PIPE)
    p.communicate(f'{root_password}\n'.encode())


def unmount_raw_file(mount_point):
    p = subprocess.Popen(['sudo', '-S', 'umount', mount_point], stdin=subprocess.PIPE)
    p.communicate(f'{root_password}\n'.encode())
    
    p = subprocess.Popen(['sudo', '-S', 'qemu-nbd', '-d', '/dev/nbd0'], stdin=subprocess.PIPE)
    p.communicate(f'{root_password}\n'.encode())


def list_php_files(base_directory, firmware_data_dir):
    php_files = []
    for root, dirs, files in os.walk(base_directory):
        for file in files:
            if file.endswith('.php'):
                php_files.append(os.path.join(root, file))

    with open(firmware_data_dir + os.sep + 'php-files.txt', 'w+') as f:
        for php_file in php_files:
            f.write(f"{php_file}\n")


def run_instrumentation(firmware_fs_path, firmware_data_dir):
    list_php_files(firmware_fs_path, firmware_data_dir)
    p = subprocess.Popen(["sudo", "-S", "php", os.path.join(os.path.abspath(os.path.dirname(__file__)), "exec_filter.php"), 
                          "-i", firmware_data_dir + os.sep + 'php-files.txt', 
                          "-o", firmware_data_dir + os.sep + 'exec-files.txt'], stdin=subprocess.PIPE)
    p.communicate(f'{root_password}\n'.encode())
    
    with open("config.json", "r") as f:
        json_conf = json.load(f)

    json_conf['exec-file'] = firmware_data_dir + os.sep + 'exec-files.txt'
    json_conf['php-files'] = firmware_data_dir + os.sep + 'php-files.txt'

    with open("config.json", "w+") as f:
        json.dump(json_conf, f)

    p = subprocess.Popen(["sudo", "-S", "php", os.path.join(os.path.abspath(os.path.dirname(__file__)), "instrument_php_files.php")], 
                         stdin=subprocess.PIPE)
    p.communicate(f'{root_password}\n'.encode())


def main():
    firmware_data_dir = os.path.abspath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "firmwares_data", firmware_name))
    os.makedirs(firmware_data_dir, exist_ok=True)

    emulated_firmwares = f"{firmadyne_path}{os.sep}firmadyne{os.sep}scratch"
    if emulation_engine == EmulationEngine.FIRMAE:
        emulated_firmwares = f"{firmae_path}{os.sep}scratch"
    emulated_firmware_dirs = []
    for emu_dir in os.listdir(emulated_firmwares):
        if emu_dir.isnumeric():
            emulated_firmware_dirs.append(int(emu_dir))
    emulated_firmware_dir = max(emulated_firmware_dirs)

    backup_folder(f"{emulated_firmwares}{os.sep}{emulated_firmware_dir}")
    firmware_fs_path = f"{emulated_firmwares}{os.sep}{emulated_firmware_dir}{os.sep}image_fs"
    p = subprocess.Popen(["sudo", "-S", "mkdir", "-p", firmware_fs_path], stdin=subprocess.PIPE)
    p.communicate(f'{root_password}\n'.encode())
    try:
        mount_raw_file(f"{emulated_firmwares}{os.sep}{emulated_firmware_dir}{os.sep}image.raw", firmware_fs_path)
        run_instrumentation(firmware_fs_path, firmware_data_dir)
    finally:
        unmount_raw_file(firmware_fs_path)


if __name__ == "__main__":
    main()
