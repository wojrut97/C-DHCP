import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
import os
import random
from client import Client
from scapy.all import *
import time

client = Client()
time.sleep(2)
while True:
    client.sendUnencryptedSolicit()
    client.awaitUnencryptedDHCPv6Message()
    client.sendUnencryptedRequest()
    client.awaitUnencryptedDHCPv6Message()
    client.assignIP()