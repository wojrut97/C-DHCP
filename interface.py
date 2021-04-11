import uuid

class Interface:
    def __init__(self, name):
        self.name = name
    
    def getMAC(self):
        return uuid.getnode().to_bytes(16, "big")
        