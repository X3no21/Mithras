#!/bin/bash

# expose internal address on port 8080 of wlan0
sudo iptables -t nat -A PREROUTING -p tcp -i wlan0 -j DNAT --to-destination <internal-ip>
sudo iptables -t nat -o wlan0 -A POSTROUTING -j MASQUERADE
sudo iptables -A FORWARD -p tcp -i wlan0 -j ACCEPT

# change default gateway from eth0 to wlan0
ip route
sudo ip route del default via <from-routes-default> dev eth0
sudo ip route add default via <IP-address-wlan0> dev wlan0

# restore default
sudo ip route del default via <IP-address-wlan0> dev wlan0
sudo ip route add default via <from-previous-routes> dev eth0
