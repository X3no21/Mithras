#!/bin/bash

# create access point
sudo nmcli con add con-name hotspot ifname wlan0 type wifi ssid "Test-IoT"

# setup access point password
sudo nmcli con modify hotspot wifi-sec.key-mgmt wpa-psk
sudo nmcli con modify hotspot wifi-sec.psk "raspberry"

# set up wifi access point
sudo nmcli con modify hotspot 802-11-wireless.mode ap 802-11-wireless.band bg ipv4.method shared

# change ip address
sudo nmcli con modify hotspot ipv4.method shared ipv4.addresses 192.168.0.1/24
sudo nmcli con down hotspot
sudo nmcli con up hotspot

# connect to existing access point
sudo nmcli dev wifi connect network-ssid password "network-password"
