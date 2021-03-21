import socket
import config
import random
from host import Host
from packet import packet
from interface import interface


class Client(Host):
    def __init__(self):
        super(Client, self).__init__()
        self.config_params = config.config("client_dhcp.conf")
        self.client_port = 10068
        self.server_port = 10067
        self.sock = self.setupSocket()
        self.broadcast = ('<broadcast>', self.server_port)
        self.interface = interface()
        self.ongoing_transactions = {}

    def setupSocket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", self.client_port))
        return sock
        
    def sendDiscover(self):
        discover = self.createDiscover()
        print("message: ", discover.print())
        self.sock.sendto(discover.compress(), self.broadcast)

    def createDiscover(self):
        discover = packet()
        discover.OP = bytes([0x01])
        discover.HTYPE = bytes([0x01])
        discover.HLEN = bytes([0x06])
        discover.HOPS = bytes([0x00])
        discover.XID = self.generateXID()
        discover.SECS = bytes([0x00, 0x00])
        discover.FLAGS = bytes([0x80, 0x00])
        discover.CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        discover.YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        discover.SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        discover.GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        discover.CHADDR1 = self.interface.getMAC()
        discover.CHADDR2 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) 
        discover.CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00]) 
        discover.Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        discover.DHCPOptions1 = bytes([0x53 , 0x01 , 0x01])
        discover.DHCPOptions2 = bytes([0x50 , 0x04 , 0xC0, 0xA8, 0x01, 0x64])
        return discover
        
    def generateXID(self):
        return random.randint(0x00, 0xFFFFFFFF).to_bytes(4, "big")

