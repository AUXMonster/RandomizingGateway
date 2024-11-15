#!/usr/bin/env python3
from fcntl import ioctl
import ipaddress
from scapy.all import IP, TCP
import os
import socket
import struct
import sys
import threading
import time
import random

REDIRECT_DNS = 1
REDIRECT_IP = 1

ip_whitelist = ["127.0.0.0/8"]
ip_whitelist = [ipaddress.ip_network(i, False) for i in ip_whitelist]

addrs = dict()
num_addrs =  2 ** 16
def new_addr():
	addr = ipaddress.ip_address(192*2**24 + 168*2**16 + random.randint(0, num_addrs))
	if addr in addrs:
		return new_addr()
	return addr

#   Read directly from network interface
def openTun(name):
	LINUX_IFF_TUN = 0x0001
	LINUX_IFF_NO_PI = 0x1000
	LINUX_TUNSETIFF = 0x400454CA
	
	tun = open("/dev/net/tun", 'r+b', buffering=0)
	ifs = struct.pack("16sH22s", name, LINUX_IFF_TUN | LINUX_IFF_NO_PI, b"")
	ioctl(tun, LINUX_TUNSETIFF, ifs)

	return tun

interior = openTun(b"interior")
exterior = openTun(b"exterior")
decoy = openTun(b"decoy")
bridge = {interior:exterior, exterior:interior}
def swap(addr):
	addr = ipaddress.ip_address(addr)
	for network in ip_whitelist:
	    if addr in network:
	        return addr
	if not addr in addrs:
		alt_addr = new_addr()
		addrs[addr] = alt_addr
		addrs[alt_addr] = addr
		numKeys = int(len(addrs.keys()) / 2)
		print(f"{numKeys} keys used ({100.0 * numKeys / num_addrs}%). Total number of keys cannot exceed {num_addrs}")
	return addrs[addr]

def monitor(interface, name):
	while True:
		msg = interface.read(2**16)
		msg = IP(msg)
		msg.len = None
		msg.chksum = None
		msg.payload.len = None
		msg.payload.chksum = None
		msg.payload.payload.length = None #This causes it
		
		if (hasattr(msg.payload, "sport") and (msg.payload.sport == 53 or msg.payload.dport == 53)):
			#   This is a DNS message. Don't redirect it.
			if (msg.payload.sport == 53):
				# This is a DNS response. Change the records.
				if hasattr(msg.payload.payload, "an"):
					for i in range(msg.payload.payload.ancount):
						if (msg.payload.payload.an[i].type == 1) and REDIRECT_DNS:
							new_addr = str(swap(msg.payload.payload.an[i].rdata))
							msg.payload.payload.an[i].rdata = new_addr
		elif REDIRECT_IP:
			#	This isn't DNS. Redirect it.
			addr = str(swap(msg.src if interface == exterior else msg.dst))
			if interface == exterior:
				msg.src = addr
			else:
				msg.dst = addr
		bridge[interface].write(bytes(msg))

def warn(interface):
	#s = socket.fromfd(interface.fileno(), socket.AF_INET, socket.SOCK_STREAM)
	while True:
		data = interface.read(2**16)
		p = IP(interface.read(2**16))
		s = p.getlayer(TCP)
		if s:
			p.src, p.dst = p.dst, p.src
			s.dport, s.sport = s.sport, s.dport
			s.seq, s.ack = 0 , s.seq + 1
			s.flags = "AR"
			s.chksum = None
			s.window = 0
			interface.write(bytes(p))

threads = [
	threading.Thread(target=monitor, args=(interior, "Interior")),
	threading.Thread(target=monitor, args=(exterior, "Exterior")),
	threading.Thread(target=warn, args=(decoy, )),
	]
for t in threads:
	t.start()
for t in threads:
	t.join()
