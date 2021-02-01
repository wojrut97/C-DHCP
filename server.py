import socket
import config
import packet

class server:
    def __init__(self):
        self.config_params = config.config("server_dhcp.conf")
        self.client_port = 10068
        self.server_port = 10067
        self.sock = self.setup_socket()
        self.response = None

    def setup_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((self.get_server_ip(), self.server_port))
        return sock

    def get_server_ip(self):
        # proper interface ip TODO
        return ""
        

    def await_discover(self):
        data, addr = self.sock.recvfrom(1024)
        received_packet = packet.packet().decode(data)
        print("Received ", received_packet, " from ", addr)
