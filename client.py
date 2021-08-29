import socket

from cryptography.x509.extensions import TLSFeature
import config
import random
import time
from scapy.all import *
from scapy.layers.tls.all import *
from host import Host
from interface import Interface
import string


class Client(Host):
    def __init__(self):
        super(Client, self).__init__()
        self.config_params = config.config("client_dhcp.conf")
        self.interface = Interface(self.config_params.interface)
        self.transaction_history = {}
        self.MAC= self.interface.getRandomMAC()
        self.nieWiemCoTo = "ff:ff:ff:ff:ff:ab"

        #Me
        self.certificate_path = "./certificates/client.crt"
        self.certificate = self.loadCertificate(self.certificate_path)
        self.private_key_path = "./keys/klient.key"
        self.private_key = self.loadPrivateKey(self.private_key_path)

    def sendCertRequest(self):
        layer2 = Ether()
        layer3 = IPv6()
        layer4 = UDP()
        layer2.dst = self.interface.getRandomMAC()
        layer3.dst = self.servers_multicast_address
        layer3.src = self.ip
        layer4.sport = self.ssl_port
        layer4.dport = self.ssl_port

        cert_message = layer2 / layer3 / layer4 / TLS13Certificate(self.certificate.public_bytes(serialization.Encoding.PEM))
        key_message = layer2 / layer3 / layer4 / self.half_key

        sendp([cert_message, key_message], iface="enp0s8")

    def awaitValidHelloMessage(self):
        # czy to nie jest identiko server client?
        print("oczekuje na odpowiedz!")
        listening = True
        while listening:
            received = sniff(iface="enp0s8", filter="dst port " + str(self.ssl_port), count=2)
            self.retrieveMessageData(received)
            if self.verifyCertificate() == 0:
                listening = False
        print("Authorized server hello obtained!")
        self.combineKeyTogether()
        self.createEncryptionKey()
    
    def combineKeyTogether(self):
        print("moj klucz: ", self.half_key)
        print("Ich klucz: ", self.retrieved_half_key)
        self.full_key = self.half_key + self.retrieved_half_key
        print("Nasz klucz: ", self.full_key)

    def createSolicit(self, trid):
        layer2 = Ether()
        layer3 = IPv6()
        layer4 = UDP()
        sol = DHCP6_Solicit()
        cid = DHCP6OptClientId()
        iana = DHCP6OptIA_NA()

        layer2.dst = self.interface.getRandomMAC()
        layer3.dst = self.servers_multicast_address
        layer3.src = self.ip
        layer4.sport = self.client_port
        layer4.dport = self.server_port
        sol.trid = trid
        cid.duid = self.createDUID()
        iana.T1 = 0
        iana.T2 = 0

        data_to_encrpyt = sol / iana / cid
        unencrypted_message = layer2 / layer3 / layer4 / data_to_encrpyt
        self.updateTransactions(unencrypted_message)
        encrypted_data = self.fernet.encrypt(bytes(data_to_encrpyt))
        message = layer2 / layer3 / layer4 / encrypted_data

        return message

    def createRequest(self, trid):
        layer2 = Ether()
        layer3 = IPv6()
        layer4 = UDP()
        sol = DHCP6_Request()
        cid = DHCP6OptClientId()
        sid = self.last_message["DHCP6OptServerId"]
        iana = DHCP6OptIA_NA()
        iaaddr = self.last_message["DHCP6OptIAAddress"]

        layer2.dst = self.interface.getRandomMAC()
        layer3.dst = self.last_message["IPv6"].src
        layer3.src = self.ip
        layer4.sport = self.client_port
        layer4.dport = self.server_port
        sol.trid = trid
        cid.duid = self.createDUID()
        iana.T1 = 0
        iana.T2 = 0

        data_to_encrpyt = sol / cid / sid / iana 
        unencrypted_message = layer2 / layer3 / layer4 / data_to_encrpyt
        self.updateTransactions(unencrypted_message)
        encrypted_data = self.fernet.encrypt(bytes(data_to_encrpyt))
        message = layer2 / layer3 / layer4 / encrypted_data
        return message

    def sendSolicit(self):
        trid = self.generateTRID()
        message = self.createSolicit(trid)
        print("Sending Solicit...")
        try:
            sendp(message, iface="enp0s8")
            self.last_message = message
        except:
            print("An error occured while sending Solicit")

    def sendRequest(self):
        trid = self.last_message.trid
        message = self.createRequest(trid)
        print("Sending Request...")
        try:
            sendp(message, iface="enp0s8")
            self.last_message = message
        except:
            print("An error occured while sending Request")

    def retrievedValidAdvertise(self):
        msgtype = self.last_message["DHCP6_Advertise"].msgtype
        trid = self.last_message["DHCP6_Advertise"].trid
        print("Klucze: ", self.transaction_history.keys())
        print("trid: ", trid)
        self.last_message.show2()
        if msgtype == 0x2:
            self.updateTransactions(self.last_message)
            return True
        else:
            return False

    def retrievedValidReply(self):
        msgtype = self.last_message["DHCP6_Reply"].msgtype
        trid = self.last_message["DHCP6_Reply"].trid
        if msgtype == 0x7:
            self.updateTransactions(self.last_message)
            return True
        else:
            return False

    def assignIP(self):
        print("Assigning IP: ", self.last_message["DHCP6OptIAAddress"].addr)

    def generateTRID(self):
        return random.randint(0x00, 0xFFFFFFFF)

