import random
import struct
import time
import hashlib
from scapy.all import *

class Packet():
    def __init__(self):
        self.layer2 = Ether()
        self.layer3 = IPv6()
        self.layer4 = UDP()

        self.layer2.dst = "ff:ff:ff:ff:ff:ab"
        self.layer3.dst = "ff02::1:2"
        self.layer4.dport = 547
        self.layer4.sport = 546

    def Solicit(self, trid):
        sol = DHCP6_Solicit()
        sol.trid = trid
        self.layer4.dport = 547
        self.layer4.sport = 546
        self.packet = self.layer2 / self.layer3 / self.layer4 / sol

    def Advertise(self, trid):
        adv = DHCP6_Advertise()
        adv.trid = trid
        self.packet = self.packet / adv

    def Request(self, trid):
        req = DHCP6_Request()
        req.trid = trid
        self.packet = self.packet / req

    def Reply(self, trid):
        rep = DHCP6_Reply()
        rep.trid = trid
        self.packet = self.packet / rep

    def get_packet(self):
        return self.packet