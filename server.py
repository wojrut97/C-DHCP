import socket
import config
import threading
import ipaddress
import arpreq
import time
from host import Host
from packet import Packet

class Server(Host):
    def __init__(self):
        super(Server, self).__init__()
        self.config_params = config.config("server_dhcp.conf")
        self.client_port = 68
        self.server_port = 67
        self.broadcast = ('<broadcast>', self.client_port)
        self.sock = self.setupSocket()
        self.ongoing_transactions = {}
        self.known_hosts = {}
        self.unused_addresses = self.scanFreeAddresses()


    def setupSocket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((self.getIP(), self.server_port))
        return sock

    def sendOffer(self):
        offer = self.createOffer()
        print("Send message: ")
        offer.print()
        self.sock.sendto(offer.compress(), self.broadcast)

    def createOffer(self):
        offer = self.response
        offer.OP = bytes([0x02])
        offer.YIADDR = self.chooseIP(self.response.CHADDR1)
        return offer

    def sendAck(self):
        ack = self.createOffer()
        print("Send message: ")
        ack.print()
        self.sock.sendto(ack.compress(), self.broadcast)

    def createAck(self):
        ack = self.response
        ack.OP = bytes([0x02])
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
            time.sleep(0.05)
        return unused_addresses

