import socket
import config
import packet

class client:
    def __init__(self):
        self.config_params = config.config("client_dhcp.conf")
        self.client_port = 10068
        self.server_port = 10067
        self.sock = self.setup_socket()
        self.broadcast = ('<broadcast>', self.server_port)

    def setup_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", self.client_port))
        return sock
        
    def send_DHCP_discover(self):
        message = packet.packet().DHCP_discover()
        self.sock.sendto(message, self.broadcast)

    def await_offer(self):
        pass
        

