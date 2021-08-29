import socket
import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat import primitives
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import config
import threading
import ipaddress
import arpreq
import time
from interface import Interface
from host import Host
from scapy.all import *
from cryptography import x509
from scapy.layers.tls.all import *

class Server(Host):
    def __init__(self):
        super(Server, self).__init__()
        self.config_params = config.config("server_dhcp.conf")
        self.interface = Interface(self.config_params.interface)
        self.transaction_history = {}
        self.known_hosts = {}
        # self.unused_addresses = self.scanFreeAddresses()
        self.MAC= self.interface.getRandomMAC()
        #Me
        self.certificate_path = "./certificates/server.crt"
        self.certificate = self.loadCertificate(self.certificate_path)
        self.private_key_path = "./keys/server.key"
        self.private_key = self.loadPrivateKey(self.private_key_path)

    def awaitValidHelloMessage(self):
        print("Listening...")
        listening = True
        while listening:
            received = sniff(iface="enp0s8", filter="dst port " + str(self.ssl_port), count=2)
            self.retrieveMessageData(received)
            if self.verifyCertificate() == 0:
                listening = False
        print("Authorized client hello obtained!")
        self.combineKeyTogether()
        self.createEncryptionKey()

    def combineKeyTogether(self):
        print("Typ otrzymanego: ", type(self.retrieved_half_key))
        print("Typ mojego: ", type(self.half_key))
        self.full_key = self.retrieved_half_key + self.half_key 
        print("Nasz klucz: ", self.full_key)

    def sendEncryptedHalfKeyAndCertificate(self):
        encrypted_half_key = self.retrieved_public_key.encrypt(
            self.half_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        layer2 = Ether()
        layer3 = IPv6()
        layer4 = UDP()
        layer2.dst = self.interface.getRandomMAC()
        layer3.dst = self.servers_multicast_address
        layer3.src = self.ip
        layer4.sport = self.ssl_port
        layer4.dport = self.ssl_port

        cert_message = layer2 / layer3 / layer4 / TLS13Certificate(self.certificate.public_bytes(serialization.Encoding.PEM))
        key_message = layer2 / layer3 / layer4 / encrypted_half_key

        sendp([cert_message, key_message], iface="enp0s8")

    def retrievedValidSolicit(self):
        msgtype = self.last_message["DHCP6_Solicit"].msgtype
        trid = self.last_message["DHCP6_Solicit"].trid
        if msgtype == 0x1:
            self.updateTransactions(self.last_message)
            return True
        else:
            return False

    def retrievedValidRequest(self):
        msgtype = self.last_message["DHCP6_Request"].msgtype
        trid = self.last_message["DHCP6_Request"].trid
        if msgtype == 0x3:
            self.updateTransactions(self.last_message)
            return True
        else:
            return False

    def sendAdvertise(self):
        trid = self.last_message["DHCP6_Solicit"].trid
        message = self.createAdvertise(trid)
        print("Sending Advertise...")
        try:
            sendp(message, iface="enp0s8")
            self.last_message = message
        except:
            print("An error occured while sending Advertise")

    def sendReply(self):
        trid = self.last_message["DHCP6_Request"].trid
        message = self.createReply(trid)
        print("Sending Reply...")
        try:
            sendp(message, iface="enp0s8")
            self.last_message = message
        except:
            print("An error occured while sending Reply")

    def createAdvertise(self, trid):
        layer2 = Ether()
        layer3 = IPv6()
        layer4 = UDP()
        adv = DHCP6_Advertise()
        sid = DHCP6OptServerId()
        cid = self.last_message["DHCP6OptClientId"]
        iana = DHCP6OptIA_NA()
        iaaddr = DHCP6OptIAAddress()

        layer2.dst = self.interface.getRandomMAC()
        layer3.dst = self.last_message["IPv6"].src
        layer3.src = self.ip
        layer4.sport = self.server_port
        layer4.dport = self.client_port
        adv.trid = trid
        sid.duid = self.createDUID()
        iana.T1 = 100
        iana.T2 = 200
        iaaddr.addr = self.chooseIP()
        iaaddr.preflft = 3600
        iaaddr.validlft = 7200


        data_to_encrpyt = adv / cid / sid / iana / iaaddr
        print("Czy tu sie wywala: ", bytes(data_to_encrpyt))
        unencrypted_message = layer2 / layer3 / layer4 / data_to_encrpyt
        self.updateTransactions(unencrypted_message)
        encrypted_data = self.fernet.encrypt(bytes(data_to_encrpyt))
        message = layer2 / layer3 / layer4 / encrypted_data
        return message

    def createReply(self, trid):
        layer2 = Ether()
        layer3 = IPv6()
        layer4 = UDP()
        rep = DHCP6_Reply()
        sid = self.last_message["DHCP6OptServerId"]
        iana = self.last_message["DHCP6OptIA_NA"]
        iaaddr = self.last_message["DHCP6OptIAAddress"]
        cid = self.last_message["DHCP6OptClientId"]

        layer2.dst = self.interface.getRandomMAC()
        layer3.dst = self.last_message["IPv6"].src
        layer3.src = self.ip
        layer4.sport = self.server_port
        layer4.dport = self.client_port
        rep.trid = trid

        data_to_encrpyt = rep / sid / cid / sid / iana / iaaddr
        unencrypted_message = layer2 / layer3 / layer4 / data_to_encrpyt
        self.updateTransactions(unencrypted_message)
        encrypted_data = self.fernet.encrypt(bytes(data_to_encrpyt))
        message = layer2 / layer3 / layer4 / encrypted_data
        return message

    def chooseIP(self):
        return ipaddress.IPv6Address('bbbb:cccc::') + random.randint(1, 1000)

    # def scanFreeAddresses(self):
    #     unused_addresses = []
    #     busy_addresses = []
    #     #TODO: fix hardcoded address
    #     network = ipaddress.IPv6Address('bbbb:cccc::')
    #     for _ in range(3):
    #         for i in range(1, 100):
    #             host = network + i
    #             # mac = arpreq.arpreq(host)
    #             if host in busy_addresses:
    #                 continue
    #             elif True:
    #                 unused_addresses.append(host)
    #             else:
    #                 busy_addresses.append(host)
    #             time.sleep(0.005)
    #     print("lol dlugosc: ", len(unused_addresses), "Ostatni: ", unused_addresses[-1])
    #     return unused_addresses

