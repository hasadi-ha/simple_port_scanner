# Let It Begin!

import time
import logging
from scapy.all import *

target = input('Enter host to be scanned: ')

print('Starting scan on host: ')

closed_ports = 0
open_ports = []


def check_IP_active(target):
    icmp = IP(dst=target)/ICMP()
    resp = sr1(icmp, timeout=10)
    if resp == None:
        return false
    else:
        return True
