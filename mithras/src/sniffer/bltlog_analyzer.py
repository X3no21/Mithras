import time

import pyshark
from loguru import logger
import sys
import os
from os.path import dirname, abspath

sys.path.append(dirname(dirname(abspath(__file__))))

LOCAL_LOGFILE_PATH = '/tmp/mithras_log_bluetooth.log'
REMOTE_LOGFILE_PATH = '/data/misc/bluetooth/logs/btsnoop_hci.log'


class BltLogAnalyzer:

    def __init__(self, adb_driver=None):
        self._keep_alives = {}
        self.adb_driver = adb_driver

    def _pull_log(self):
        if not os.path.exists(LOCAL_LOGFILE_PATH):
            open(LOCAL_LOGFILE_PATH, 'x')
        self.adb_driver.adb_su_cmd('cp {} /sdcard/my_blt_log'.format(REMOTE_LOGFILE_PATH))
        self.adb_driver.adb_cmd(['pull', '/sdcard/my_blt_log', LOCAL_LOGFILE_PATH])
        return LOCAL_LOGFILE_PATH

    def remove_log(self):
        if os.path.isfile(LOCAL_LOGFILE_PATH):
            os.remove(LOCAL_LOGFILE_PATH)

    def detect_keep_alives(self):
        logger.info('Detecting BL keep-alives')
        capture = pyshark.FileCapture(self._pull_log())

        for packet in capture:
            if hasattr(packet, 'hci_h4'):
                # direction is SENT
                if packet.hci_h4.direction == '0x00000000':
                    if packet.length not in self._keep_alives:
                        self._keep_alives[packet.length] = set()

                    if hasattr(packet, 'btatt') and hasattr(packet.btatt, 'value'):
                        self._keep_alives[packet.length].add(str(packet.btatt.value))

        capture.close()
        if not capture.eventloop.is_closed():
            capture.eventloop.close()
        self.remove_log()

    def _is_keep_alive(self, packet):
        if hasattr(packet, 'hci_h4'):
            if packet.hci_h4.direction == '0x00000000' and hasattr(packet, 'btatt'):
                if packet.length in self._keep_alives:
                    # if str(packet.btatt.value) in self._keep_alives[packet.length]:
                    return True
        return False

    def get_new_sent_packet_ts(self, start_ts):
        try:
            capture = pyshark.FileCapture(self._pull_log())
        except:
            logger.error("FileCapture error")
            return None
        timestamp = None
        for packet in capture:
            if hasattr(packet, 'hci_h4'):
                # direction is SENT
                if packet.hci_h4.direction == '0x00000000':
                    if not self._is_keep_alive(packet) and float(packet.sniff_timestamp) > start_ts:
                        logger.debug('New BL packet: {}'.format(packet.sniff_timestamp))
                        timestamp = float(packet.sniff_timestamp)
                        break

        capture.close()
        if not capture.eventloop.is_closed():
            capture.eventloop.close()
        self.remove_log()
        if timestamp is None:
            logger.debug('No new BL packet')
        return timestamp
