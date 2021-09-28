# Master's Thesis
# Analysis of security and privacy of IP network auto-configuration services.
# Gdansk University of Technology 2021
# Author: Wojciech Rutkowski

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat import primitives
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import config
import ipaddress
import arpreq
from interface import Interface
from host import Host
from scapy.all import *
from cryptography import x509
from scapy.layers.tls.all import *

# This class represents secure and insecure DHCP Server 
# Implements methods for Advertise and Reply sending and creation
# Implements methods for Solicit and Request verification
# Contains unencrypted versions of above functionalities


class Server(Host):
    def __init__(self):
        super(Server, self).__init__()
        self.config_params = config.config("server_dhcp.conf")
        self.interface_name = self.config_params.interface
        self.interface = Interface(self.interface_name)
        self.transaction_history = {}
        self.known_hosts = {}
        self.receive_port = self.server_port
        self.send_port = self.client_port
        self.handshake_receive_port = self.handshake_server_port
        self.handshake_send_port = self.handshake_client_port
        self.ip_repeat = 10
        self.MAC = self.interface.getRandomMAC()
        self.ip = self.getIP()

        #Me
        self.certificate_path = "./certificates/server.crt"
        self.certificate = self.loadCertificate(self.certificate_path)
        self.private_key_path = "./keys/server.key"
        self.private_key = self.loadPrivateKey(self.private_key_path)

        #Listeners
        self.startHandshakeListener()
        self.startDHCPv6Listener()

####C-DHCP part####

    def startHandshakeListener(self):
        listener = threading.Thread(target=self.handshakeListener, daemon=True)
        listener.start()

    def handshakeListener(self):
        print("Handshake listener ready!")
        while True:
            received = sniff(iface=self.interface_name, filter="dst port " + str(self.handshake_receive_port), count=1)
            print("received:", received)
            self.handshake_message_buffer.append(received[0])

    def combineKeyTogether(self):
        self.full_key = self.retrieved_half_key + self.half_key 

    def retrievedValidSolicit(self):
        msgtype = self.last_message["DHCP6_Solicit"].msgtype
        if msgtype == 0x1:
            self.updateTransactions(self.last_message)
            print("Valid Solicit obtained!")
            return True
        else:
            return False

    def retrievedValidRequest(self):
        msgtype = self.last_message["DHCP6_Request"].msgtype
        trid = self.last_message["DHCP6_Request"].trid
        if msgtype == 0x3 and trid in self.transaction_history:
            self.updateTransactions(self.last_message)
            print("Valid Request obtained!")
            return True
        else:
            return False

    def sendAdvertise(self):
        trid = self.last_message["DHCP6_Solicit"].trid
        message = self.createAdvertise(trid)
        print("Sending Advertise...")
        try:
            sendp(message, iface=self.interface_name)
            self.last_message = message
        except:
            print("An error occured while sending Advertise")

    def sendReply(self):
        trid = self.last_message["DHCP6_Request"].trid
        message = self.createReply(trid)
        print("Sending Reply...")
        try:
            sendp(message, iface=self.interface_name)
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
        for _ in range(self.ip_repeat):
            ip = ipaddress.IPv6Address('bbbb:cccc::') + random.randint(1, 1000)
            if self.isIPUnused(ip):
                return ip
        print("Could not get unused IP address!")

    def isIPUnused(self, ip):
        return True

####Unencrypted DHCPv6 part####

    def retrievedUnencryptedSolicit(self):
        msgtype = self.last_message["DHCP6_Solicit"].msgtype
        if msgtype == 0x1:
            self.updateTransactions(self.last_message)
            print("Unencrypted Solicit obtained!")
            return True
        else:
            return False

    def retrievedUnencryptedRequest(self):
        msgtype = self.last_message["DHCP6_Request"].msgtype
        trid = self.last_message["DHCP6_Request"].trid
        if msgtype == 0x3 and trid in self.transaction_history:
            self.updateTransactions(self.last_message)
            print("Unencrypted Request obtained!")
            return True
        else:
            return False

    def sendUnencryptedAdvertise(self):
        trid = self.last_message["DHCP6_Solicit"].trid
        message = self.createUnencryptedAdvertise(trid)
        print("Sending Advertise...")
        try:
            sendp(message, iface=self.interface_name)
            self.updateTransactions(message)
            self.last_message = message
        except:
            print("An error occured while sending Advertise")

    def sendUnencryptedReply(self):
        trid = self.last_message["DHCP6_Request"].trid
        message = self.createUnencryptedReply(trid)
        print("Sending Reply...")
        try:
            sendp(message, iface=self.interface_name)
            self.updateTransactions(message)
            self.last_message = message
        except:
            print("An error occured while sending Reply")

    def createUnencryptedAdvertise(self, trid):
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

        data = adv / cid / sid / iana / iaaddr
        message = layer2 / layer3 / layer4 / data

        return message

    def createUnencryptedReply(self, trid):
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

        data = rep / sid / cid / sid / iana / iaaddr
        message = layer2 / layer3 / layer4 / data

        return message