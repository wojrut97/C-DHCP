import socket
import config
import threading
import ipaddress
import arpreq
import time
from interface import Interface
from host import Host
from packet import Packet

class Server(Host):
    def __init__(self):
        super(Server, self).__init__()
        self.config_params = config.config("server_dhcp.conf")
        self.interface = Interface(self.config_params.interface)
        self.client_port = 67
        self.server_port = 68
        self.listening_sock = self.setupSocket("", self.server_port)
        self.writing_sock = self.setupSocket("", self.client_port)
        self.broadcast = ('<broadcast>', self.client_port)
        self.ongoing_transactions = {}
        self.known_hosts = {}
        self.unused_addresses = self.scanFreeAddresses()


    def sendOffer(self):
        offer = self.createOffer()
        print("Sending offer...")
        offer.print()
        self.sendMessage(offer)

    def createOffer(self):
        offer = self.response
        offer.OP = bytes([0x02])
        offer.YIADDR = self.chooseIP(self.response.CHADDR)
        offer.clearOptions()
        offer.addOption(53, 2)
        offer.addOption(255, 1)
        return offer

    def sendAck(self):
        ack = self.createOffer()
        print("Sending ack...")
        ack.print()
        self.sendMessage(ack)

    def createAck(self):
        ack = self.response
        ack.OP = bytes([0x02])
        ack.clearOptions()
        ack.addOption(53, 4)
        ack.addOption(255, 1)
        return ack    

    def chooseIP(self, mac):
        ip = self.unused_addresses[-1]
        return self.ipToBytes(ip)

    def ipToBytes(self, ip):
        ip_as_string = str(ip)
        splitted_ip = ip_as_string.split(".")
        for i in range(len(splitted_ip)):
            splitted_ip[i] = int(splitted_ip[i])
        return bytes(splitted_ip)

    def scanFreeAddresses(self):
        unused_addresses = []
        busy_addresses = []
        network_ip = self.config_params.network_ip
        network = ipaddress.IPv4Network(network_ip)
        for _ in range(3):
            for host in network.hosts():
                mac = arpreq.arpreq(host)
                if host in busy_addresses:
                    continue
                elif mac is None:
                    unused_addresses.append(host)
                else:
                    busy_addresses.append(host)
                time.sleep(0.005)
        # print("free addresses: ", unused_addresses)
        return unused_addresses

