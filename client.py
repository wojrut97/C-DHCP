import socket
import config
import packet

class client:
    def __init__(self):
        self.config_params = config.config("client_dhcp.conf")
        self.port = 10002
        self.sock = self.setup_socket()
        self.broadcast = ("<broadcast>", self.port)

    def setup_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", self.port))
        return sock
        
    def DHCP_discover(self):
        message = packet.packet().DHCP_discover()
        self.sock.sendto(message, self.broadcast)

    def await_offer(self):
        pass
        

