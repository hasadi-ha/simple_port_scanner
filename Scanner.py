# Let It Begin!

import time
import logging
from scapy.all import *
logging.getLogger("scrapy.runtime").setLevel(logging.ERROR)

target = input('Enter host to be scanned: ')

print('Starting scan on host: ')

closed_ports = 0
open_ports = []


def check_IP_active(target):
    icmp = IP(dst=target)/ICMP()
    resp = sr1(icmp, timeout=10)
    if resp == None:
        return False
    else:
        return True


if __name__ == '__main__':
    start_time = time.time()
    ports = range(1, 500)
    if check_IP_active(target):
        print("Host %s is up, start scanning" % target)
        for port in ports:
            src_port = RandShort()
            p = IP(dst=target)/TCP(sport=src_port, dport=port, flags='S')
            resp = sr1(p, timeout=10)
            if str(type(resp)) == "<type 'NoneType'>":
                closed_ports += 1
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12:
                    send_rst = sr(IP(dst=target)/TCP(sport=src_port,
                                                     dport=port, flags='AR'), timeout=10)
                    open_ports.append(port)
                elif resp.getlayer(TCP).flags == 0x14:
                    closed_ports += 1
        duration = time.time() - start_time
        print("%s Scan completed in %fs" % (target, duration))
        if len(open_ports) != 0:
            for pop in open_ports:
                print("%d open" % pop)
        print("%d closed ports in %d total port scanned" %
              (closed_ports, len(ports)))
    else:
        print("Host %s is Down" % target)
