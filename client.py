import socket
import config
import random
import time
from host import Host
from packet import Packet
from interface import Interface


class Client(Host):
    def __init__(self):
        super(Client, self).__init__()
        self.config_params = config.config("client_dhcp.conf")
        self.interface = Interface(self.config_params.interface)
        self.client_port = 67
        self.server_port = 68
        self.listening_sock = self.setupSocket("", self.client_port)
        self.writing_sock = self.setupSocket("", self.server_port)
        self.broadcast = ('<broadcast>', self.server_port)
        self.ongoing_transactions = {}

        
    def sendDiscover(self):
        discover = self.createDiscover()
        print("message: ", discover.print())
        self.sendMessage(discover)


    def createDiscover(self):
        discover = Packet()
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
        
    def sendRequest(self):
        request = self.createRequest()
        print("message: ", request.print())
        self.sendMessage(request)

    def createRequest(self):
        request = self.response
        request.OP = bytes([0x01])
        request.SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        request.GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        request.CHADDR1 = self.interface.getMAC()
        request.CHADDR2 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) 
        request.CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00]) 
        request.Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        request.DHCPOptions1 = bytes([0x53 , 0x01 , 0x01])
        request.DHCPOptions2 = bytes([0x50 , 0x04 , 0xC0, 0xA8, 0x01, 0x64])
        return request

    def generateXID(self):
        return random.randint(0x00, 0xFFFFFFFF).to_bytes(4, "big")

