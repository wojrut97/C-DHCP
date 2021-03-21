import socket
import config
from packet import packet

class Host:
    def __init__(self):
        self.response = packet()
        self.ongoing_transactions = {}
        self.sock = None

    def getIP(self):
        # proper interface ip TODO
        return ""

    def updateTransactions(self, XID):
        if XID not in self.ongoing_transactions:
            self.ongoing_transactions[XID] = 1
        else:
            if self.ongoing_transactions[XID] == 3:
                self.ongoing_transactions.pop(XID, None)
            else:
                self.ongoing_transactions[XID] += 1

    def awaitMessage(self):
        data, addr = self.sock.recvfrom(1024)
        self.response = packet().decode(data)
        print("Received message from: ", addr, " containig:")
        self.response.print()
        self.updateTransactions(self.response.XID)
        print("Transaction table: ", self.ongoing_transactions)

