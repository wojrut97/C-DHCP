import socket
import config
import packet

class client:
    def __init__(self):
        self.config_params = config.config("client_dhcp.conf")
        
    def DHCP_discover(self):
        message = packet.packet().DHCP_discover()
        print(message)

