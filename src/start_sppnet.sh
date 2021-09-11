#!/bin/bash

# In /etc/sysctl.conf add this lines :
# net.ipv6.conf.lo.disable_ipv6 = 1
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.all.autoconf = 0
# net.ipv6.conf.default.disable_ipv6 = 1
# net.ipv6.conf.default.autoconf = 0

sudo sysctl -p

sudo gnome-terminal -e "python3.5 graph/server.py"

sudo python3.5 main.py
