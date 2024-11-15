#!/usr/bin/env python3

from subprocess import run
import re
import os

"""	In order to set up the virtual rotues correctly, we should gather
some information about the current network configuration.
"""
#	default via 12.228.226.1 dev wlp3s0 proto dhcp src 12.228.227.234 metric 600 
route = run(["ip", "route", "show", "default"],capture_output=1,text=1)

match_str = "(via )(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
match = re.search(match_str, route.stdout)
next_hop = match.group(2)
print(f"Next Hop: {next_hop}")

match_str = "(src )(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
match = re.search(match_str, route.stdout)
default_route = match.group(2)
print(f"Default Route: {default_route}")

match_str = "(dev )(\S+)"
match = re.search(match_str, route.stdout)
default_interface = match.group(2)
print(f"Default Interface: {default_interface}")

"""	Some config changes need to be made to kernel networking. Some
security measures, as well as optimizations, will need to be disabled,
otherwise the strange fuckery which we are about to perform will not
work. Linux will try to short-cirtcuit the meandering path we've set
up, and it also thinks we're malicious because what we're doing is
deceptive to the hardware and the user.

These changes are idempotent, so it's ok to apply them multiple times.
"""

#	Enable IPv4 forwarding
run(["sysctl", "net.ipv4.ip_forward=1"])
#	Allow us to set Exterior's source address to that of the default
#	network interface.
run(["sysctl", "net.ipv4.conf.all.accept_local=1"])
#	I don't understand how this works, but it is necessary.
run(["sysctl", "net.ipv4.ip_early_demux=0"])
#	There is no IPv6 support yet, so you should be sure to disable it.
run(["sysctl", "net.ipv6.conf.all.disable_ipv6=1"])

"""	Named tables make things a lot easier because we don't have to
keep track of table numbers when we set up routes and route rules.
The first time we run setup, these named tables need to be added to
IP's config.
"""

named_route_string = """
# Automatically inserted by Ryan Raymond's program
117 incoming
343 outgoing
"""

if run(["ip", "route", "show", "table", "incoming"]).returncode == 255:
	with open("/etc/iproute2/rt_tables", "a") as file:
		file.write(named_route_string)

run(["ip", "tuntap", "delete", "name", "interior", "mode", "tun"])
run(["ip", "tuntap", "delete", "name", "exterior", "mode", "tun"])
#run(["ip", "tuntap", "delete", "name", "decoy", "mode", "tun"])

run(["ip", "tuntap", "add", "name", "interior", "mode", "tun"])
run(["ip", "tuntap", "add", "name", "exterior", "mode", "tun"])
run(["ip", "tuntap", "add", "name", "decoy", "mode", "tun"])

#run(["ip", "link", "add", "decoy", "type", "veth", "peer", "name", "decoy_in"])

#	Try removing this later. I am not certain that it's needed.
run(["ip", "address", "add", "10.1.0.1/16", "dev", "interior"])
run(["ip", "address", "add", "10.2.0.1/16", "dev", "exterior"])
run(["ip", "address", "add", "192.168.0.0/16", "dev", "decoy"])

run(["ip", "link", "set", "interior", "up"])
run(["ip", "link", "set", "exterior", "up"])
run(["ip", "link", "set", "decoy", "up"])

#run(["ip", "route", "delete", "default"])
#run(["ip", "route", "delete", "192.168.0.0/16"])

run(["ip", "rule", "delete", "lookup", "local"])
run(["ip", "rule", "delete", "lookup", "default"])

run(["ip", "rule", "add", "iif", "exterior", "priority", "10", "lookup", "main"])
run(["ip", "rule", "add", "fwmark", "2", "priority", "40", "lookup", "incoming"])
run(["ip", "rule", "add", "iif", "interior", "priority", "20", "lookup", "local"])
run(["ip", "rule", "add", "priority", "50", "lookup", "outgoing"])
run(["ip", "rule", "add", "priority", "30", "iif", "decoy", "lookup", "incoming"])

run(["ip", "route", "add", "default", "dev", "interior", "src", default_route, "table", "outgoing"])
#run(["ip", "route", "add", "default", "dev", default_interface, "via", next_hop, "table", "outgoing"])
run(["ip", "route", "add", "default", "dev", "exterior", "table", "incoming"])
#run(["ip", "route", "add", "192.168.0.0/16", "dev", "decoy", "table", "outgoing"])

run(["iptables", "-t", "mangle", "-A", "PREROUTING", "-j", "MARK", "--set-mark", "2"])

update_script = """#!/usr/bin/env python3
import re
from subprocess import run as run

route = run(["ip", "route", "show", "default"], capture_output = 1, text = 1)
match_str = "(src )(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
address = re.search(match_str, route.stdout).group(2)



run(["ip", "route", "delete", "default", "table", "outgoing"])
run(["ip", "route", "add", "default", "dev", "interior", "src", address, "table", "outgoing"])
"""

with open("/etc/NetworkManager/dispatcher.d/10-update.py", "w") as f:
	f.write(update_script)
run(["chmod", "755", "/etc/NetworkManager/dispatcher.d/10-update.py"])
print("All done!")
