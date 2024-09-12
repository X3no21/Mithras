#!/bin/bash

dns-sd -R "D-Link HNAP Service" _dhnap._tcp. local 80 "model_number=DIR-868L" "hw_version=B1" "mac=7A:2C:6B:A6:47:72" "wlan0_ssid=Test-IoT" "wlan1_ssid=Test-IoT" "version=0202" "dcs=Medeleine" "mydlink=true" "hnf=false" "m_GUI=false" "bundle_number=1" "mve=DZM00" "dms=master" "dct=100" >/dev/null 2>&1 &