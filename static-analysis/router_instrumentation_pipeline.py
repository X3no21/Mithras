import os
import shutil
import subprocess
import configparser
import pexpect
import json
import time


def backup_folder(folder):
    dst_bck = f"{folder}.bck"
    if os.path.exists(dst_bck):
        return
    p = subprocess.Popen(["sudo", "-S", "cp", "-r", folder, dst_bck], stdin=subprocess.PIPE)
    p.communicate(b'raspberry\n')
    print(f"Folder {folder} copied to {dst_bck}")


def mount_raw_file(image_raw_path, mount_point):
    if not os.path.exists(mount_point):
        os.makedirs(mount_point)

    p = subprocess.Popen(['sudo', '-S', 'modprobe', 'nbd'], stdin=subprocess.PIPE)
    p.communicate(b'raspberry\n')

    p = subprocess.Popen(['sudo', '-S', 'qemu-nbd', '--format=raw', '-c', '/dev/nbd0', image_raw_path], stdin=subprocess.PIPE)
    p.communicate(b'raspberry\n')

    p = subprocess.Popen(['sudo', '-S', 'mkdir', '-p', mount_point], stdin=subprocess.PIPE)
    p.communicate(b'raspberry\n')

    p = subprocess.Popen(['sudo', '-S', 'mount', '/dev/nbd0p1', mount_point], stdin=subprocess.PIPE)
    p.communicate(b'raspberry\n')


def unmount_raw_file(mount_point):
    p = subprocess.Popen(['sudo', '-S', 'umount', mount_point], stdin=subprocess.PIPE)
    p.communicate(b'raspberry\n')
    
    p = subprocess.Popen(['sudo', '-S', 'qemu-nbd', '-d', '/dev/nbd0'], stdin=subprocess.PIPE)
    p.communicate(b'raspberry\n')
    
    
def check_linux_root_structure(base_directory, threshold=0.7):
    linux_dirs = ['bin', 'etc', 'var', 'home', 'lib', 'usr', 'sbin', 'opt', 'root', 'tmp', 'boot', 'dev', 'mnt', 'proc', 'run', 'srv', 'sys']
    total_dirs = len(linux_dirs)
    
    for root, dirs, files in os.walk(base_directory):
        present_dirs = sum(1 for d in linux_dirs if os.path.isdir(os.path.join(root, d)))
        presence_ratio = present_dirs / total_dirs
        
        if presence_ratio >= threshold:
            return root
    return ""


def execute_firmadyne(firmadyne_path, firmware_path, emulate):
    if emulate:
        backup_folder(f"{firmadyne_path}{os.sep}firmadyne{os.sep}scratch{os.sep}1")
        return f"{firmadyne_path}{os.sep}firmadyne{os.sep}scratch{os.sep}1"
    else:
        subprocess.run([f'binwalk', "-e1", firmware_path], check=True)
        return os.path.dirname(firmware_path) + os.sep + "_" + os.path.basename(firmadyne_path)
    
    
def list_php_files(base_directory, firmware_data_dir):
    php_files = []
    for root, dirs, files in os.walk(base_directory):
        for file in files:
            if file.endswith('.php'):
                php_files.append(os.path.join(root, file))

    with open(firmware_data_dir + os.sep + 'php-files.txt', 'w') as f:
        for php_file in php_files:
            f.write(f"{php_file}\n")
            
    
def run_instrumentation(firmware_fs_path, firmware_data_dir):
    list_php_files(firmware_fs_path, firmware_data_dir)
    p = subprocess.Popen(["sudo", "-S", "php", "exec_filter.php", "-i", firmware_data_dir + os.sep + 'php-files.txt', 
                          "-o", firmware_data_dir + os.sep + 'exec-files.txt'], stdin=subprocess.PIPE)
    p.communicate(b"raspberry\n")

    #config = configparser.ConfigParser()
    #config.read("./graph_service/conf.ini")
    #config.set("DEFAULT", "graph_file_path", firmware_data_dir + os.sep + "call-graph")
    #with open("./graph_service/conf.ini", "w+") as f:
    #    config.write(f)
    #p_flask = subprocess.Popen(["./venv/bin/python", "run_flask.py"])
    #time.sleep(1)
    
    #config = configparser.ConfigParser()
    #config.read("./call_graph/conf.ini")
    #config.set("DEFAULT", "php-files", firmware_data_dir + os.sep + "php-files.txt")
    #with open("./call_graph/conf.ini", "w+") as f:
    #    config.write(f)

    #cwd = os.getcwd()
    #os.chdir("call_graph")
    #p = subprocess.Popen(["sudo", "-S", "php", "compute_call_graph.php"], stdin=subprocess.PIPE)
    #p.communicate(b"raspberry\n")
    #p_flask.kill()
    #os.chdir(cwd)

    with open("config.json", "r") as f:
        json_conf = json.load(f)

    json_conf['exec-file'] = firmware_data_dir + os.sep + 'exec-files.txt'
    json_conf['php-files'] = firmware_data_dir + os.sep + 'php-files.txt'

    with open("config.json", "w+") as f:
        json.dump(json_conf, f)

    p = subprocess.Popen(["sudo", "-S", "php", "instrument_php_files.php"], stdin=subprocess.PIPE)
    p.communicate(b"raspberry\n")
    

def main(firmadyne_path, firmware_path, emulate):
    firmware_data_dir = os.path.abspath("./firmwares_data" + os.sep + os.path.splitext(os.path.basename(firmware_path))[0])
    os.makedirs(firmware_data_dir, exist_ok=True)
    firmware_fs_path = execute_firmadyne(firmadyne_path, firmware_path, emulate)
    if emulate:
        firmware_fs_path = os.path.join(firmware_fs_path, "image_fs")
        p = subprocess.Popen(["sudo", "-S", "mkdir", firmware_fs_path], stdin=subprocess.PIPE)
        p.communicate(b"raspberry\n")

        mount_raw_file(f"{firmadyne_path}{os.sep}firmadyne{os.sep}scratch{os.sep}1{os.sep}image.raw", firmware_fs_path)
        
    run_instrumentation(firmware_fs_path, firmware_data_dir)
    if emulate:
        unmount_raw_file(firmware_fs_path)


if __name__ == "__main__":
    firmware_path = "/home/raspberry/git/FirmAE/firmwares/DIR846enFW100A53DLA-Retail.bin"
    firmadyne_path = "/home/raspberry/git/firmware-analysis-toolkit"
    emulate = True
    
    main(firmadyne_path, firmware_path, emulate)
