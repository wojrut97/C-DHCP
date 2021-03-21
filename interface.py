import uuid

class interface():

    
    def getMAC(self):
        return uuid.getnode().to_bytes(6, "big")
        