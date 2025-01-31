import multiprocessing
import subprocess
import traceback

from loguru import logger
import zipfile
from src.layout_agent.utils.utils import EmulatorLauncher
import hmac
import hashlib
import time
import argparse
import json
import sys
import re
import os

from flask import Flask, request, Response
import requests
import enum
from ipaddress import ip_address, ip_network


class EmulationEngine(enum.Enum):
    FIRMADYNE = "firmadyne"
    FIRMAE = "firmae"
    DEFAULT = "default"

    @classmethod
    def from_string(cls, value: str):
        return cls.__members__.get(value.upper(), cls.DEFAULT)


PRIVATE_NETWORKS = [
    ip_network('10.0.0.0/8'),
    ip_network('172.16.0.0/12'),
    ip_network('192.168.0.0/16'),
    ip_network('100.64.0.0/10'),
    ip_network('169.254.0.0/16'),
    ip_network('198.18.0.0/15'),
    ip_network('192.0.0.0/24'),
    ip_network('192.0.2.0/24'),
    ip_network('192.88.99.0/24'),
    ip_network('198.51.100.0/24'),
    ip_network('203.0.113.0/24'),
    ip_network('240.0.0.0/4')
]

if not os.path.exists(os.path.join(os.path.abspath(os.path.dirname(__file__)), "logs_proxy")):
    os.makedirs("logs_proxy")
my_logger = logger.bind(name="test_firmware")
my_logger.remove()
my_logger.add(os.path.join(os.path.abspath(os.path.dirname(__file__)), "logs_proxy", "logfile.log"), rotation="10 MB",
              compression="zip", level='DEBUG')
my_logger.add(sys.stdout, level='INFO')
my_logger.add(sys.stdout, level='ERROR')
my_logger.add(sys.stdout, level='WARNING')

adb_path = os.path.join(os.environ.get("ANDROID_HOME"), "platform-tools", "adb")
build_tools_path = os.path.join(os.environ.get("ANDROID_HOME"), "build-tools")

build_tool_newer = max([elem for elem in os.listdir(build_tools_path)])
aapt_path = os.path.join(os.environ.get("ANDROID_HOME"), "build-tools", str(build_tool_newer), "aapt")

app = Flask(__name__)

TARGET_SERVER_URL = '192.168.0.1'
STATIC_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.otf',
                     '.eot']
session = {}


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    global session
    headers = dict(request.headers)
    cookies = dict(request.cookies)
    host = request.host.split(':')[0]
    try:
        ip = ip_address(host)
        is_private = any(ip in network for network in PRIVATE_NETWORKS) or host == 'localhost' or ip.is_loopback
    except ValueError:
        is_private = host == 'localhost'

    if is_private:
        target_url = f"http://{TARGET_SERVER_URL}/{path}"
        headers['Host'] = TARGET_SERVER_URL
        if "Origin" in headers:
            headers['Origin'] = headers['Origin'].replace(host, TARGET_SERVER_URL)
        if "Referer" in headers:
            headers['Referer'] = headers['Referer'].replace(host, TARGET_SERVER_URL)

        headers_to_pop = set()
        for header in headers:
            if "Sec-" in header:
                headers_to_pop.add(header)

        for header in headers_to_pop:
            del headers[header]

        hnap_header_present = False
        for header in headers:
            if header.lower() == "hnap_auth":
                hnap_header_present = True
                break

        if not hnap_header_present:
            soapaction_header = ""
            for header in headers:
                if header.lower() == "soapaction":
                    soapaction_header = header

            if soapaction_header != "" and "uid" in cookies and cookies["uid"] in session:
                key = ""
                if "PrivateKey" in cookies:
                    key = cookies["PrivateKey"]
                elif "uid" in cookies and cookies["uid"] in session:
                    key = session[cookies["uid"]]
                current_timestamp = int(time.time()) % 2000000000
                auth = hmac.new(key.encode(), f'{current_timestamp}{headers[soapaction_header]}'.encode(),
                                hashlib.md5).hexdigest().upper()
                headers["hnap_auth"] = f'{auth} {current_timestamp}'
    else:
        target_url = request.url

    my_logger.debug("Url: " + target_url + " - - Request Cookie: " + str(cookies))
    my_logger.debug("Url: " + target_url + " - - Request Headers: " + str(headers))
    my_logger.debug("Url: " + target_url + " - - Request Body: " + str(request.get_data()))

    try:
        if request.method == 'GET':
            response = requests.get(target_url, headers=headers, params=request.args, cookies=cookies)
        elif request.method == 'POST':
            response = requests.post(target_url, headers=headers, data=request.get_data(), params=request.args,
                                     cookies=cookies)
        elif request.method == 'PUT':
            response = requests.put(target_url, headers=headers, data=request.get_data(), params=request.args,
                                    cookies=cookies)
        elif request.method == 'DELETE':
            response = requests.delete(target_url, headers=headers, params=request.args, cookies=cookies)
        else:
            return Response('Method not supported', status=405)

        match1 = re.search(
            r"[\s\S]*<Challenge>(.*)</Challenge>[\s\S]*<Cookie>(.*)</Cookie>[\s\S]*<PublicKey>(.*)</PublicKey>[\s\S]*",
            response.content.decode())
        if match1:
            challenge = match1.group(1)
            cookie = match1.group(2)
            publickey = match1.group(3)

            session[cookie] = hmac.new(publickey.encode(), challenge.encode(), hashlib.md5).hexdigest().upper()

        response_headers = dict(response.headers)
        response_body = response.content
        response_headers['Content-Length'] = str(len(response_body))

        if 'Transfer-Encoding' in response_headers:
            del response_headers['Transfer-Encoding']

        my_logger.debug("Url: " + target_url + " Response headers: " + str(response_headers))
        my_logger.debug("Url: " + target_url + " Response body: " + str(response_body))
        return Response(response_body, status=response.status_code, headers=response_headers)

    except requests.exceptions.ChunkedEncodingError as e:
        return Response('Chunked Encoding Error', status=502)


def proxy_static_resource(url, headers, cookies):
    try:
        response = requests.get(url, headers=headers, cookies=cookies, stream=True)
        response.raise_for_status()
        return Response(response.raw, status=response.status_code, headers=dict(response.headers),
                        direct_passthrough=True)
    except requests.exceptions.RequestException as e:
        return Response('Error fetching static resource', status=502)


def run_iot_proxy():
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')
    app.run(host='0.0.0.0', port=8080, debug=False)


def get_package_name(apk_path):
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk:
            result = subprocess.run([aapt_path, 'dump', 'badging', apk_path], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.startswith("package: name="):
                    return line.split("'")[1]
        return None
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        return None


def is_app_installed(package_name, device_id=None):
    cmd = [adb_path]
    if device_id:
        cmd.extend(['-s', device_id])
    cmd.extend(['shell', 'pm', 'list', 'packages', '|', 'grep', package_name])

    result = subprocess.run(cmd, capture_output=True, text=True)
    return package_name in result.stdout


def install_apk(apk_path, device_id=None):
    cmd = [adb_path, 'install', '-g', apk_path]
    if device_id:
        cmd.insert(1, '-s')
        cmd.insert(2, device_id)
    install_result = subprocess.run(cmd, capture_output=True, text=True)
    if "Success" in install_result.stdout:
        return True
    else:
        return False


def main(config_path: str):
    if not os.path.exists(config_path):
        logger.error("The config file does not exist")
        return

    with open(config_path, "r") as f:
        config_json = json.load(f)

    with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), "router_mapping.json"), "r") as f:
        firmware_mapping = json.load(f)

    firmware_name = os.path.splitext(os.path.basename(config_json["firmware_path"]))[0]

    global TARGET_SERVER_URL
    TARGET_SERVER_URL = firmware_mapping[firmware_name]["ip_address"]
    config_json["firmware_name"] = firmware_name
    with open(config_path, "w") as f:
        json.dump(config_json, f)

    emulation_engine = EmulationEngine.from_string(config_json["emulation_engine"])
    if emulation_engine == EmulationEngine.DEFAULT:
        print("Emulation engine not valid")
        sys.exit(1)

    emu = EmulatorLauncher(config_json["root_password"], "normal", emulation_engine, config_json["firmware_path"],
                           config_json["firmware_vendor"], config_json["device_name"], 5554)
    try:
        subprocess.Popen([sys.executable, "log_server.py"])
        emu.start_emulator()
        subprocess.run([adb_path, "-s", config_json["device_id"], "root"], stderr=subprocess.DEVNULL)

        mdns_apk_path = os.path.join(os.path.dirname(os.path.abspath(os.path.dirname(__file__))), "apps", "mdns.apk")
        companion_apk_path = config_json["smartphone_apk_path"]
        mdns_apk_package_name = get_package_name(mdns_apk_path)
        if not is_app_installed(mdns_apk_package_name):
            install_apk(mdns_apk_path)

        companion_apk_package_name = get_package_name(companion_apk_path)
        if not is_app_installed(companion_apk_package_name):
            install_apk(companion_apk_path)

        device_model = "DIR-868L"
        if firmware_name in firmware_mapping:
            device_model = firmware_mapping[firmware_name]["model"]

        subprocess.run([adb_path, "-s", config_json["device_id"], "shell", "am", "force-stop", mdns_apk_package_name],
                       stderr=subprocess.DEVNULL)

        subprocess.run([adb_path, "-s", config_json["device_id"], "shell", "am", "broadcast", "-a",
                        f"{mdns_apk_package_name}.START_MDNS_SERVICE",
                        "-n", f"{mdns_apk_package_name}/{mdns_apk_package_name}.receivers.MdnsReceiver",
                        "--es", "model_number", device_model])

        subprocess.run([adb_path, "-s", config_json["device_id"], "reverse", "tcp:80", "tcp:8080"],
                       stderr=subprocess.DEVNULL)

        logger.info(f"Analyzing firmware: {firmware_name}")
        flask_p = None
        try:
            flask_p = multiprocessing.Process(target=run_iot_proxy)
            flask_p.start()
            subprocess.call([sys.executable, "run.py", config_path, "MANUAL_ANALYSIS"])
        except:
            logger.error(f"Error analyzing firmware: {firmware_name}")
            logger.error(traceback.format_exc())
            if flask_p:
                flask_p.terminate()
    finally:
        emu.terminate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-cf", type=str, default=os.path.join(os.path.abspath(os.path.dirname(__file__)), "config.json"))
    args = parser.parse_args()

    main(args.cf)
