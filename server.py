import socket
import config
import threading
import ipaddress
import arpreq
import time
from host import Host
from packet import packet

class Server(Host):
    def __init__(self):
        super(Server, self).__init__()
        self.config_params = config.config("server_dhcp.conf")
        self.client_port = 10068
        self.server_port = 10067
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
        print("message: ", offer.print())
        self.sock.sendto(offer.compress(), self.broadcast)

    def createOffer(self):
        offer = self.response
        offer.OP = bytes([0x02])
        offer.YIADDR = self.chooseIP(self.response.CHADDR1)
        return offer

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
                    # print("Unused: ", host)
                else:
                    busy_addresses.append(host)
                    # print("Used: ", host, "MAC: ", mac)
                time.sleep(0.005)
            time.sleep(0.05)
        # print("busy_addresses: ", busy_addresses)
        return unused_addresses

