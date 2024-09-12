import configparser
import multiprocessing
import subprocess
import traceback
import shutil

from loguru import logger
import hmac
import hashlib
import time
import argparse
import json
import sys
import os
import re

from flask import Flask, request, Response
import requests

app = Flask(__name__)

TARGET_SERVER_URL = '10.0.4.1'
STATIC_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.otf', '.eot']
session = {}


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    global session
    headers = dict(request.headers)
    headers['Host'] = TARGET_SERVER_URL
    if "Origin" in headers:
        headers['Origin'] = headers['Origin'].replace("127.0.0.1", TARGET_SERVER_URL)
    if "Referer" in headers:
        headers['Referer'] = headers['Referer'].replace("127.0.0.1", TARGET_SERVER_URL)

    headers_to_pop = set()
    for header in headers:
        if "Sec-" in header:
            headers_to_pop.add(header)

    for header in headers_to_pop:
        del headers[header]

    cookies = dict(request.cookies)
    url = f"http://{TARGET_SERVER_URL}/{path}"

    if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
        return proxy_static_resource(url, headers, cookies)

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

    logger.info("Url: " + url + " - - Request Cookie: " + str(cookies))
    print()
    logger.info("Url: " + url + " - - Request Headers: " + str(headers))
    print()
    logger.info("Url: " + url + " - - Request Body: " + str(request.get_data()))
    print()

    try:
        if request.method == 'GET':
            response = requests.get(url, headers=headers, params=request.args, cookies=cookies)
        elif request.method == 'POST':
            response = requests.post(url, headers=headers, data=request.get_data(), params=request.args, cookies=cookies)
        elif request.method == 'PUT':
            response = requests.put(url, headers=headers, data=request.get_data(), params=request.args, cookies=cookies)
        elif request.method == 'DELETE':
            response = requests.delete(url, headers=headers, params=request.args, cookies=cookies)
        else:
            return Response('Method not supported', status=405)

        match1 = re.search(r"[\s\S]*<Challenge>(.*)</Challenge>[\s\S]*<Cookie>(.*)</Cookie>[\s\S]*<PublicKey>(.*)</PublicKey>[\s\S]*",
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

        logger.info("Url: " + url + " Response headers: " + str(response_headers))
        print()
        logger.info("Url: " + url + " Response body: " + str(response_body))
        print()
        return Response(response_body, status=response.status_code, headers=response_headers)

    except requests.exceptions.ChunkedEncodingError as e:
        return Response('Chunked Encoding Error', status=502)


def proxy_static_resource(url, headers, cookies):
    try:
        response = requests.get(url, headers=headers, cookies=cookies, stream=True)
        response.raise_for_status()
        return Response(response.raw, status=response.status_code, headers=dict(response.headers), direct_passthrough=True)
    except requests.exceptions.RequestException as e:
        return Response('Error fetching static resource', status=502)


def run_flask():
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')
    app.run(host='0.0.0.0', port=80, debug=False)


def main(firmware_name: str, config_path: str, algorithm: str):
    if not os.path.exists(config_path):
        logger.error("The config file does not exist")
        return

    with open(config_path, "r") as f:
        config_json = json.load(f)

    config_layout_path = config_json["cf_layout_path"]
    if not os.path.exists(config_layout_path):
        logger.error("The config layout_agent file does not exist")
        return

    config_payload_path = config_json["cf_payload_path"]
    if not os.path.exists(config_payload_path):
        logger.error("The config payload_agent file does not exist")
        return

    shutil.copy(config_layout_path, os.path.dirname(config_layout_path) + os.sep + "config.ini")

    config_layout = configparser.ConfigParser()
    config_layout.read(os.path.dirname(config_layout_path) + os.sep + "config_default.ini")
    config_layout["DEFAULT"]["algo"] = algorithm

    with open(os.path.dirname(config_layout_path) + os.sep + "config.ini", "w") as f:
        config_layout.write(f)

    config_payload = configparser.ConfigParser()
    config_payload.read(os.path.dirname(config_payload_path) + os.sep + "config_default.ini")
    config_payload["DEFAULT"]["php_files"] = os.path.join(os.path.dirname(config_payload_path), "firmware_infos", firmware_name, "php-files.txt")
    config_payload["DEFAULT"]["algo"] = algorithm

    with open(os.path.dirname(config_payload_path) + os.sep + "config.ini", "w") as f:
        config_payload.write(f)

    config_json["firmware_name"] = firmware_name
    with open(config_path, "w") as f:
        json.dump(config_json, f)

    logger.info(f"Analyzing firmware: {firmware_name} - Algorithm: {algorithm}")

    flask_p = None
    try:
        flask_p = multiprocessing.Process(target=run_flask)
        flask_p.start()
        subprocess.call([sys.executable, "run.py", config_path, "FUZZING"])
    except:
        logger.error(f"Error analyzing firmware: {firmware_name}")
        logger.error(traceback.format_exc())
        if flask_p:
            flask_p.terminate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-firmware_name", type=str, default="DIR846enFW100A53DLA-Retail")
    parser.add_argument("-cf", type=str, default="/Users/x3no21/Documents/git/Mithras/mithras/config.json")
    parser.add_argument("-algo", type=str, default="SAC")
    args = parser.parse_args()

    main(args.firmware_name, args.cf, args.algo)
