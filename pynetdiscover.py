#!/usr/bin/env python

import scapy
import sys
import signal
import socket
import re
import os
import time
import logging

try:
	from netaddr import *
except ImportError:
	print 'netaddr package is missing: pip install netaddr or aptitude install python-netaddr'
	sys.exit(1)
try:
	import logging
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
	from scapy.all import srp,conf,ARP,Ether,sniff
except ImportError:
	print 'scapy package is missing: pip install scapy or aptitude install python-scapy'
	sys.exit(1)
try:
	import argparse
except ImportError:
	print 'argparse package is missing: pip install argparse or aptitude install python-argparse'
	sys.exit(1)

# Usage: netdiscover [-i device] [-r range | -l file | -p] [-s time] [-n node] [-c count] [-f] [-d] [-S] [-P] [-C]
# x  -i device: your network device
# x  -r range: scan a given range instead of auto scan. 192.168.6.0/24,/16,/8
#   -l file: scan the list of ranges contained into the given file
#   -p passive mode: do not send anything, only sniff
# x -F filter: Customize pcap filter expression (default: "arp")
# x -s time: time to sleep between each arp request (miliseconds)
#   -n node: last ip octet used for scanning (from 2 to 253)
# x -c count: number of times to send each arp reques (for nets with packet loss)
#   -f enable fastmode scan, saves a lot of time, recommended for auto
# - -d ignore home config files for autoscan and fast mode
#   -S enable sleep time supression betwen each request (hardcore mode)
# x -P print results in a format suitable for parsing by another program
#   -L in parsable output mode (-P), continue listening after the active scan is completed

# If -r, -l or -p are not enabled, netdiscover will scan for common lan addresses.

CLEAR='/usr/bin/clear'

parser = argparse.ArgumentParser(description='pynetdiscover')
parser.add_argument('-i', '--iface', nargs='?', type=str, help='your network device', default='eth0')

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-r', '--range', nargs='?', type=str, help='scan a given range')
group.add_argument('-l', '--file', nargs='?', type=str, help='scan the list of ranges contained into the given file')
group.add_argument('-p', '--passive', help='do not send anything, only sniff', action='store_true')

parser.add_argument('-F', '--filter', nargs='?', type=str, help='Customize pcap filter expression (default: "arp")', default='arp')
parser.add_argument('-c', '--count', nargs='?', type=int, help='number of times to send each arp request (for nets with packet loss)', default=0)
parser.add_argument('-P', '--print', type=str, help='print results in a format suitable for parsing by another program', default=True)

args = parser.parse_args()

if os.geteuid() != 0:
	print "This script must be run as root."
	sys.exit(1)

conf.iface=args.iface
conf.verb=0
args.range = "10.1.1.0/24"

#os.system(CLEAR)

def getConstructor(mac, oui):
	constructor = ""
	if oui:
		mac = re.sub(':', '-', mac).upper()[0:7]
		try:
			constructor = re.findall(mac + ".*", oui)[0].split('\t')[-1]
		except:
			contructor = "Unknown"
	return constructor

def printSorted(machines):
	for i in sorted(machines.iterkeys(), key=lambda a: socket.inet_aton(a)):
		psrc = i
		hwsrc = machines[i]
		print "%s\t%s\t%s" % (psrc, hwsrc, getConstructor(hwsrc,oui))

def signal_handler(signal, frame):
	end_time = time.time()
	print "\nExiting... Elapsed : %d seconds" % (end_time-start_time)
	sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

start_time = time.time()
packets = [ Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="%s" % i) for i in IPNetwork(args.range).iter_hosts() ]

ans, unans = srp(packets, timeout=2, retry=args.count)

machines = {}
for pkt in ans:
	pkt = pkt[1][ARP]
	machines[pkt.psrc] = pkt.hwsrc

ouilist = True
try: 
	oui = open("oui.txt")
	oui = oui.read()
except IOError:
	ouilist = False
	print "warning : oui.txt was not found, can't resolve mac addresses, download it with -d"

printSorted(machines)

def arp_monitor_callback(pkt):
	if ARP in pkt and pkt[ARP].op in (1,2) and pkt[ARP].psrc not in machines: #who-has or is-at
		machines[pkt[ARP].psrc] = pkt[ARP].hwsrc
		#os.system(CLEAR)
		#printSorted(machines)
		print "%s\t%s\t%s" % (pkt[ARP].psrc, pkt[ARP].hwsrc, getConstructor(pkt[ARP].hwsrc,oui))

sniff(prn=arp_monitor_callback, filter=args.filter, store=0)