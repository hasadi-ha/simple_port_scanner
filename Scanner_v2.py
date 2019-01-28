import logging
from scapy.all import *

target = input('Enter host to be scanned: ')

print('Starting scan on host: ')

port = 80

def check_IP_active(target):
    icmp = IP(dst=target)/ICMP()
    resp = sr1(icmp, timeout=10)
    if resp == None:
        return False
    else:
        return True


ports = range(1, 1024)
if check_IP_active(target):
    print("Host %s is up, start scanning" % target)
    src_port = RandShort()
    resp = sr1(IP(dst=target)/TCP(sport=src_port, dport=port, flags="S"), timeout=10)
    if (str(type(resp)) == "<type 'NoneType'>"):
        print("%d is closed" % port)
        print(str(type(resp)))
    elif (resp.haslayer(TCP)):
        print(resp.haslayer(TCP))
        if (resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=target)/TCP(sport=src_port, dport=port, flags="AR"), timeout=10)
            print("%d is open" % port)
        if (resp.getlayer(TCP).flags == 0x14):
            print("closed")
else:
    print("Host %s is down" % target)
