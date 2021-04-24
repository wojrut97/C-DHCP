import uuid

class Interface:
    def __init__(self, name):
        self.name = name
    
    def getMAC(self):
        mac = uuid.getnode()
        print("Interface's MAC: ", hex(mac))
        return mac.to_bytes(6, "little")

        