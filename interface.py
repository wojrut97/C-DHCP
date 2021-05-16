import uuid

class Interface:
    def __init__(self, name):
        self.name = name
    
    def getMAC(self):
        mac = uuid.getnode()
        mac = 0x080027166b65
        return mac.to_bytes(6, "big")

        