import uuid
import random

class Interface:
    def __init__(self, name):
        self.name = name
        self.MAC = self.getRandomMAC()

    def getMAC(self):
        mac = uuid.getnode()
        return mac.to_bytes(6, "big")

    def getRandomMAC(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
            )

    def assignIP(self, ip):
        print("Assigning ip:", ip)