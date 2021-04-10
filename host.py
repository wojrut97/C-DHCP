import socket
import config
import select
import time
from packet import Packet

class Host:
    def __init__(self):
        self.response = Packet()
        self.ongoing_transactions = {}
        self.listening_sock = None
        self.writing_sock = None
        self.broadcast = None
        self.interface = None

    def getIP(self):
        # proper interface ip TODO
        return "0.0.0.0"

    def setupSocket(self, host: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setblocking(False)
        print("TUTAJ interface: ", self.interface)
        print("TUTAJ: ", self.interface.name)
        print("TUTAJ encoded: ", self.interface.name.encode())
        if self.interface is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.name.encode())
        sock.bind((host, port))
        return sock

    def updateTransactions(self, XID):
        if XID not in self.ongoing_transactions:
            self.ongoing_transactions[XID] = 1
        else:
            if self.ongoing_transactions[XID] == 3:
                self.ongoing_transactions.pop(XID, None)
            else:
                self.ongoing_transactions[XID] += 1

    def isReadyForSend(self, socket):
        sock = select.select([], [socket], [], 0)
        return bool(len(sock[1]))

    def isReadyForRead(self, socket):
        sock = select.select([socket], [], [], 0)
        return bool(len(sock[0]))

    def sendMessage(self, packet):
        for attempt in range(10):
            if self.isReadyForSend(self.writing_sock):
                print("sock: ", self.writing_sock)
                self.writing_sock.sendto(packet.compress(), self.broadcast)
                self.updateTransactions(packet.XID)
                break
            else:
                print("Writing socket is busy, attept: ", attempt)
                time.sleep(0.01)

    def awaitMessage(self):
        for attempt in range(10):
            if self.isReadyForRead(self.listening_sock):
                print("listening_sock: ", self.listening_sock)
                data, addr = self.listening_sock.recvfrom(1024)
                self.response = packet().decode(data)
                print("Received message from: ", addr, " containig:")
                self.response.print()
                self.updateTransactions(self.response.XID)
                print("Transaction table: ", self.ongoing_transactions)
                break
            else:
                print("No data in listening socket, attept: ", attempt)
                time.sleep(0.01)
            

