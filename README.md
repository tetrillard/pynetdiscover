pynetdiscover
=============

pyNetdiscover is an active/passive address reconnaissance tool, ARP Scanner.

Inspired by the C tool Netdiscover http://nixgeneration.com/~jaime/netdiscover/

I was lazy to recompile netdiscover with an updated OUI list so I decided to
play with python and scapy.

**Work in progress**

Requirements
============
- python2.7
- scapy
- argparse
- netaddr

optional: oui.txt from http://standards.ieee.org/develop/regauth/oui/oui.txt
(can be downloaded using -d argument)

Usage
=====

As root :

> **Scan the network 192.168.0.0/24 on eth0**
>> python pynetdiscover.py -r 192.168.0.0/24 -i eth0

> **Sniff the network on eth0**
>> python pynetdiscover.py -p -i eth0

