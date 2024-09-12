import os
import subprocess
import time
import signal
import subprocess as sp
from loguru import logger
import re
import inspect
import pyshark
from multiprocessing import Process
import sys
from os.path import dirname, abspath

sys.path.append(dirname(dirname(abspath(__file__))))
from ui.config import *
from signal import SIGINT

SNIFF_SCRIPT = "./sniff.sh"
ALL_TRAFFIC_PCAP_SCRIPT = "./dump_to_pcap.sh"
FIFO_PIPE = "/tmp/sniff_data"
SNIFFING_TIME_SEC = 60 * 30
KEEPALIVE_TIMEOUT_SEC = 60 * 1
SYNC_SNIFFING = False


class StopCapturing(Exception):
    pass


class Sniffer:
    def __init__(self, config):
        self.capture_process = None
        global SYNC_SNIFFING
        self.android_ip = config['android_ip']
        self.device_ip = config['device_ip']
        self.ip_hotspot = config['ip_hot_spot']
        self.pass_ap = config['pass_ap']
        self.udid = config['device_id']
        self.keep_alive_filters = []
        self.timer = None
        self.sniffing = False
        self.pids = []
        SYNC_SNIFFING = False
        signal.signal(signal.SIGUSR2, self.terminate)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, value, traceback):
        self.clean()
        if exception_type == StopCapturing:
            return True

    def clean(self):
        # Some cleaning
        if self.timer is not None and self.timer.is_alive():
            self.timer.terminate()

        # kill local process
        cmd = "killall -s 9 sniff.sh"
        while True:
            p = sp.Popen(cmd, stdin=sp.PIPE, stderr=sp.PIPE, shell=True)
            _, e = p.communicate()
            if e:
                break

        # kill remote tcpdump
        if not self.pids:
            logger.debug("Killing all tcpdump processes")
            cmd = 'sshpass -p {} ssh root@{} "killall tcpdump"'.format(self.pass_ap, self.ip_hotspot)
            p = sp.Popen(cmd, stdin=sp.PIPE, stderr=sp.PIPE, shell=True)
            p.communicate()
        else:
            for p in self.pids:
                logger.debug("Killing tcpdump pid: " + p)
                cmd = 'sshpass -p {} ssh root@{} "kill -9 {}"'.format(self.pass_ap, self.ip_hotspot, p)
                while True:
                    p = sp.Popen(cmd, stdin=sp.PIPE, stderr=sp.PIPE, shell=True)
                    _, e = p.communicate()
                    if e:
                        break

    def timeout(self, sec):
        time.sleep(sec)
        os.kill(os.getppid(), signal.SIGUSR2)

    def detect_keepalive(self):
        sizes = {}
        try:
            for p in self.sniff_packets(sniffing_time=KEEPALIVE_TIMEOUT_SEC):
                regex = re.compile(".*length ([0-9]*):")
                match = regex.match(p)
                if match:
                    eth_len = int(match.group(1))
                    if eth_len not in sizes:
                        sizes[eth_len] = 0
                    sizes[eth_len] += 1
                    logger.info("Packet of length {} sniffed".format(str(eth_len)))
        except:
            logger.info('detecting keealive: Stop capturing')
            self.clean()

        tot_bytes = sum([x for x in sizes.values()])
        for eth_len, count in sizes.items():
            # we assume a keep alive should be sent at least one a second
            if count / float(tot_bytes) < 0.5:
                continue
            filter = "\"'(greater {} or less {})'\"".format(str(eth_len + 1), str(eth_len - 1))
            if filter not in self.keep_alive_filters:
                self.keep_alive_filters.append(filter)

    def apply_keepalive_filters(self):
        if not self.keep_alive_filters:
            return ''
        return ' and ' + ' and '.join(self.keep_alive_filters)

    def create_pipe(self):
        if os.path.exists(FIFO_PIPE):
            os.remove(FIFO_PIPE)
            time.sleep(1)
        os.mkfifo(FIFO_PIPE)

    def find_pids(self, old_pids):
        pids = self.get_opened_tcpdumps()
        self.pids = [p for p in pids if p not in old_pids]

    def get_opened_tcpdumps(self):
        cmd = "sshpass -p {} ssh root@{} \"ps | grep tcpdump\"".format(self.pass_ap, self.ip_hotspot)
        p = sp.Popen(cmd, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, shell=True)
        o, e = p.communicate()
        dumps = [x for x in o.split(b'\n') if 'grep' not in x and x]
        pids = [[y for y in x.split(b' ') if y][0] for x in dumps]
        return pids

    def start_capturing_traffic(self):
        self.create_pipe()
        path_script = os.path.dirname(__file__) + '/' + SNIFF_SCRIPT
        cmd = "{} {} {} {} {} {}&".format(path_script, self.pass_ap, self.ip_hotspot,
                                          self.android_ip, self.device_ip, self.apply_keepalive_filters())
        pids = self.get_opened_tcpdumps()
        os.system(cmd)
        time.sleep(1)
        self.find_pids(pids)

    def sniff_packets(self, sniffing_time=SNIFFING_TIME_SEC, n_packets=None):
        global SYNC_SNIFFING
        logger.info("Sniffing packets, press CTRL+C to stop (max sniffing time: {} mins)".format(
            str(sniffing_time / 60)))

        self.start_capturing_traffic()
        fifo = open(FIFO_PIPE)
        counter = 0
        SYNC_SNIFFING = True
        self.timer = Process(target=self.timeout, args=(sniffing_time,))
        self.timer.start()
        while True:
            if n_packets and counter == n_packets:
                logger.info("Sniffed {} packets".format(str(n_packets)))
                self.terminate()
            line = fifo.readline()
            counter += 1
            yield line

    def dump_all_traffic_to_pcap(self, pcap_path):
        path_script = os.path.dirname(__file__) + '/' + ALL_TRAFFIC_PCAP_SCRIPT
        cmd = "{} {} {} {}&".format(path_script, self.pass_ap, self.ip_hotspot, pcap_path)
        pids = self.get_opened_tcpdumps()
        os.system(cmd)
        time.sleep(1)
        self.find_pids(pids)

    def terminate(self, *args, **kwargs):
        global SYNC_SNIFFING
        sniffing = False
        if len(args) == 2 and args[0] == signal.SIGUSR2:
            sniffing = args[1].f_globals['SYNC_SNIFFING']
            args[1].f_globals['SYNC_SNIFFING'] = False

        if sniffing or SYNC_SNIFFING:
            SYNC_SNIFFING = False
            raise StopCapturing

        self.clean()

    def start_capturing_app_traffic(self, store_dir):
        self.capture_process = sp.Popen(['python3',
                                         os.path.abspath(os.path.dirname(__file__)) + os.sep + 'udp_exporter.py',
                                         '-p', '5123', '-w', store_dir + os.sep + "dump.pcap"],
                                        stderr=open("/dev/null", "w"))

    def stop_capturing_app_traffic(self):
        if self.capture_process:
            self.capture_process.send_signal(SIGINT)
            self.capture_process = None

    def analyze_app_network_traffic(self, start_ts, store_dir):
        try:
            capture = pyshark.FileCapture(store_dir + os.sep + 'dump.pcap')
            if capture:
                timestamp = None
                for packet in capture:
                    if float(packet.sniff_timestamp) > start_ts:
                        timestamp = float(packet.sniff_timestamp)
                        break
                return timestamp
        except Exception as e:
            logger.error(e)
        finally:
            if os.path.exists(store_dir + os.sep + 'dump.pcap'):
                os.remove(store_dir + os.sep + 'dump.pcap')

        return None


if __name__ == "__main__":
    import json

    config_path = '../experiments/wans/config_wans.json'
    with open(config_path) as fp:
        config = json.load(fp)

    print("Dumping pcap to /tmp/test_capture.pcap")
    with Sniffer(config) as sniffer:
        sniffer.dump_all_traffic_to_pcap('/tmp/test_capture.pcap')
        time.sleep(5)
        sniffer.terminate()

    print("Sniffing for 5 seconds")
    with sniffer as sn:
        for p in sn.sniff_packets(5):
            print(p)

    print("Sniffing two packets")
    with sniffer as sn:
        for p in sn.sniff_packets(n_packets=2):
            print(p)
    print("DONE")
