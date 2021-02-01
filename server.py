import socket
import config
import packet

class server:
    def __init__(self):
        self.config_params = config.config("server_dhcp.conf")
        self.port = 10003
        self.sock = self.setup_socket()

    def setup_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((self.get_server_ip(), self.port))
        return sock

    def get_server_ip(self):
        # proper interface ip TODO
        return ""
        

    def await_discover(self):
        data, addr = self.sock.recvfrom(1024)
        print("Received ", data, " from ", addr)

