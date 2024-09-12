# Setup mDNS services

This command sets up the `_dhnap._tcp` service. This service allows the companion app to discover the router inside the local network

```bash
dns-sd -R "D-Link HNAP Service" _dhnap._tcp. local 80 "model_number=DIR-868L hw_version=B1 mac=7A:2C:6B:A6:47:72 wlan0_ssid=Test-IoT wlan1_ssid=Test-IoT version=0201 dcs=24601 mydlink=true hnf=false m_GUI=false bundle_number=1 mve=DZM00 dms=master dct=100" >/dev/null 2>&1 &
```

To automatically enable the service inside the router, I generated the following systemd script:

```conf
[Unit]
Description=Register mDNS Service for D-Link Router
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/register_mdns.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

To enable the script at system startup I execute the following commands:

```bash
sudo systemctl enable mdns-register.service
sudo systemctl start mdns-register.service
```