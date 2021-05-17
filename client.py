import socket
import config
import random
import time
from host import Host
from interface import Interface
from packet import Packet


class Client(Host):
    def __init__(self, authentication):
        super(Client, self).__init__()
        self.config_params = config.config("client_dhcp.conf")
        self.interface = Interface(self.config_params.interface)
        self.sock = self.setupSocket("", self.client_port)
        self.ongoing_transactions = {}
        self.authentication = authentication

        
    def sendDiscover(self):
        discover = self.createDiscover()
        print("Sending discover...")
        # discover.print()
        self.sendMessage(discover, self.server_broadcast)


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
        discover.CHADDR = discover.macAlign(self.interface.getMAC())
        discover.Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        discover.purgeOptions()
        discover.addOption(53, 1)
        # discover.addOption(12, "virtualbox")
        discover.addOption(55, [1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42])
        discover.addOption(61, [1, 11, 32, 43, 77, 250, 12])
        if self.authentication:
            discover.addAuthenticationOption(self.config_params.password)
        discover.addOption(255, 255)
        return discover
        
    def sendRequest(self):
        request = self.createRequest()
        print("Sending request...")
        self.sendMessage(request, self.server_broadcast)

    def createRequest(self):
        request = self.response
        request.addOption(50, request.byteArrayToList(request.YIADDR))
        request.OP = bytes([0x01])
        request.SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        request.GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        request.YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        request.FLAGS = bytes([0x80, 0x00])
        request.CHADDR = request.macAlign(self.interface.getMAC())
        request.Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        request.modifyOption(53, 3)
        request.delOption(255)
        request.delOption(1)
        request.delOption(3)
        request.delOption(15)
        # request.addOption(12, "virtualbox")
        request.addOption(55, [1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42])
        request.addOption(61, [1, 11, 32, 43, 77, 250, 12])
        if self.authentication:
            request.addAuthenticationOption(self.config_params.password)
        request.addOption(255, 255)
        # request.delOption(13)
        return request

    def generateXID(self):
        return random.randint(0x00, 0xFFFFFFFF).to_bytes(4, "big")

