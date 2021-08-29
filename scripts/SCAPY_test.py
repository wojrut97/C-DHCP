from scapy.all import *
import time

dest = "fe80::1234"

base = IPv6()
base.dst = dest
base.src = "fe80::dead:beef"
# ns = ICMPv6ND_NS(tgt=dest)
# ll = ICMPv6NDOptSrcLLAddr()

ether = Ether()

pkt = ether / base



print(pkt)
pkt.show2()
sendp(pkt, iface="enp0s8")