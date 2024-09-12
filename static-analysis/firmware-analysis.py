import os
import subprocess
import argparse
import magic
from enum import Enum
import pathlib


class Operation(Enum):
    extract_firmware = "extract_firmware"
    find_php_files = "find_php_files"
    clear_fmk_dir = "clear_fmk_dir"

    def __str__(self) -> str:
        return self.value


def extract_firmware(sudo_password: str, firmware_mod_kit_path: str, firmware_path: str):
    absolute_firmware_path = os.path.abspath(firmware_path)
    previous_wd = os.path.abspath(os.getcwd())
    os.chdir(os.path.dirname(absolute_firmware_path))
    if not os.path.exists("fmk") or len(os.listdir("fmk")) == 0:
        echo_proc = subprocess.Popen(["echo", sudo_password], stdout=subprocess.PIPE)
        echo_proc.wait()
        subprocess.run(["sudo", "-S", firmware_mod_kit_path + os.sep + "extract-firmware.sh", absolute_firmware_path],
                       stdin=echo_proc.stdout)

        echo_proc = subprocess.Popen(["echo", sudo_password], stdout=subprocess.PIPE)
        echo_proc.wait()
        subprocess.run(["sudo", "-S", "chown", "-R", os.environ.get("USER"), "fmk"], stdin=echo_proc.stdout)

        echo_proc = subprocess.Popen(["echo", sudo_password], stdout=subprocess.PIPE)
        echo_proc.wait()
        subprocess.run(["sudo", "-S", "chgrp", "-R", os.environ.get("USER"), "fmk"], stdin=echo_proc.stdout)
    else:
        print("Firmware directory not empty")
    os.chdir(previous_wd)


def clear_firmware_directory(sudo_password: str, firmware_path: str):
    absolute_firmware_path = os.path.abspath(firmware_path)
    previous_wd = os.path.abspath(os.getcwd())
    os.chdir(os.path.dirname(absolute_firmware_path))
    if os.path.exists("fmk"):
        echo_proc = subprocess.Popen(["echo", sudo_password], stdout=subprocess.PIPE)
        echo_proc.wait()
        subprocess.run(["sudo", "-S", "rm", "-rf", "fmk"], stdin=echo_proc.stdout)
    os.chdir(previous_wd)


def find_php_files(output_file_path: str, firmware_path: str):
    extracted_firmware_path = os.path.dirname(firmware_path) + os.sep + "fmk"
    with open(output_file_path, "w+") as f:
        for dirpath, _, filenames in os.walk(extracted_firmware_path):
            for filename in filenames:
                if not pathlib.Path(dirpath + os.sep + filename).is_symlink() and \
                        (filename.endswith(".php") or "php" in magic.from_file(dirpath + os.sep + filename).lower()):
                    f.write(os.path.abspath(dirpath + os.sep + filename + "\n"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-op", type=str, choices=list(Operation), help="Operation to perform",
                        default="find_php_files")
    parser.add_argument("-fmk", type=str, help="Firmware Mod Kit root directory",
                        default="/home/kali/Documents/git/firmware-mod-kit")
    parser.add_argument("-fp", type=str, help="Firmware Path",
                        default="/home/kali/Downloads/DIR846enFW100A53DLA-Retail.bin")
    parser.add_argument("-olf", type=str, help="Path of the files that lists the .php files inside the firmware",
                        default="./php-files.txt")
    parser.add_argument("-p", type=str, help="Sudo Password")

    args = parser.parse_args()
    if args.op == Operation.extract_firmware.value:
        clear_firmware_directory(args.p, args.fp)
        extract_firmware(args.p, args.fmk, args.fp)
    elif args.op == Operation.find_php_files.value:
        clear_firmware_directory(args.p, args.fp)
        extract_firmware(args.p, args.fmk, args.fp)
        find_php_files(args.olf, args.fp)
    elif args.op == Operation.clear_fmk_dir.value:
        clear_firmware_directory(args.p, args.fp)
