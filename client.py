# Master's Thesis
# Analysis of security and privacy of IP network auto-configuration services.
# Gdansk University of Technology 2021
# Author: Wojciech Rutkowski

from cryptography.x509.extensions import TLSFeature
import config
import random
from scapy.all import *
from scapy.layers.tls.all import *
from host import Host
from interface import Interface

# This class represents secure and insecure DHCP Client 
# Implements methods for Solicit and Request sending and creation
# Implements methods for Advertise and Reply verification
# Contains unencrypted versions of above functionalities

class Client(Host):
    def __init__(self):
        super(Client, self).__init__()
        self.config_params = config.config("client_dhcp.conf")
        self.interface_name = self.config_params.interface
        self.interface = Interface(self.interface_name)
        self.transaction_history = {}
        self.receive_port = self.client_port
        self.send_port = self.server_port
        self.handshake_receive_port = self.handshake_client_port
        self.handshake_send_port = self.handshake_server_port
        self.ip = self.getIP()

        #Me
        self.certificate_path = "./certificates/client.crt"
        self.certificate = self.loadCertificate(self.certificate_path)
        self.private_key_path = "./keys/client.key"
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
            received = sniff(iface=self.interface_name, filter="dst port " + str(self.handshake_receive_port), count=2)
            self.handshake_message_buffer.append(received[0])
            self.handshake_message_buffer.append(received[1])

    def combineKeyTogether(self):
        self.full_key = self.half_key + self.retrieved_half_key

    def createSolicit(self, trid):
        layer2 = Ether()
        layer3 = IPv6()
        layer4 = UDP()
        sol = DHCP6_Solicit()
        cid = DHCP6OptClientId()
        iana = DHCP6OptIA_NA()

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
        req = DHCP6_Request()
        cid = DHCP6OptClientId()
        sid = self.last_message["DHCP6OptServerId"]
        iana = DHCP6OptIA_NA()

        layer3.dst = self.last_message["IPv6"].src
        layer3.src = self.ip
        layer4.sport = self.client_port
        layer4.dport = self.server_port
        req.trid = trid
        cid.duid = self.createDUID()
        iana.T1 = 0
        iana.T2 = 0

        data_to_encrpyt = req / cid / sid / iana 
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
            sendp(message, iface=self.interface_name)
            self.last_message = message
        except:
            print("An error occured while sending Solicit")

    def sendRequest(self):
        trid = self.last_message.trid
        message = self.createRequest(trid)
        print("Sending Request...")
        try:
            sendp(message, iface=self.interface_name)
            self.last_message = message
        except:
            print("An error occured while sending Request")

    def retrievedValidAdvertise(self):
        msgtype = self.last_message["DHCP6_Advertise"].msgtype
        trid = self.last_message["DHCP6_Advertise"].trid
        if msgtype == 0x2 and trid in self.transaction_history:
            self.updateTransactions(self.last_message)
            print("Valid Advertise obtained!")
            return True
        else:
            return False

    def retrievedValidReply(self):
        msgtype = self.last_message["DHCP6_Reply"].msgtype
        trid = self.last_message["DHCP6_Reply"].trid
        if msgtype == 0x7 and trid in self.transaction_history:
            self.updateTransactions(self.last_message)
            print("Valid Reply obtained!")
            return True
        else:
            return False

    def assignIP(self):
        self.interface.assignIP(self.last_message["DHCP6OptIAAddress"].addr)

    def generateTRID(self):
        return random.randint(0x00, 0xFFFFFF)

####Unencrypted DHCPv6 part####

    def createUnencryptedSolicit(self, trid):
        layer2 = Ether()
        layer3 = IPv6()
        layer4 = UDP()
        sol = DHCP6_Solicit()
        cid = DHCP6OptClientId()
        iana = DHCP6OptIA_NA()

        layer3.dst = self.servers_multicast_address
        layer3.src = self.ip
        layer4.sport = self.client_port
        layer4.dport = self.server_port
        sol.trid = trid
        cid.duid = self.createDUID()
        iana.T1 = 0
        iana.T2 = 0

        data = sol / iana / cid
        message = layer2 / layer3 / layer4 / data

        return message

    def createUnencryptedRequest(self, trid):
        layer2 = Ether()
        layer3 = IPv6()
        layer4 = UDP()
        req = DHCP6_Request()
        cid = DHCP6OptClientId()
        sid = self.last_message["DHCP6OptServerId"]
        iana = DHCP6OptIA_NA()

        layer3.dst = self.last_message["IPv6"].src
        layer3.src = self.ip
        layer4.sport = self.client_port
        layer4.dport = self.server_port
        req.trid = trid
        cid.duid = self.createDUID()
        iana.T1 = 0
        iana.T2 = 0

        data = req / cid / sid / iana 
        message = layer2 / layer3 / layer4 / data
        return message

    def sendUnencryptedSolicit(self):
        trid = self.generateTRID()
        message = self.createUnencryptedSolicit(trid)
        print("Sending Solicit...")
        try:
            sendp(message, iface=self.interface_name)
            self.updateTransactions(message)
            self.last_message = message
        except:
            print("An error occured while sending Solicit")

    def sendUnencryptedRequest(self):
        trid = self.last_message.trid
        message = self.createUnencryptedRequest(trid)
        print("Sending Request...")
        try:
            sendp(message, iface=self.interface_name)
            self.updateTransactions(message)
            self.last_message = message
        except:
            print("An error occured while sending Request")

    def retrievedUnencryptedAdvertise(self):
        msgtype = self.last_message["DHCP6_Advertise"].msgtype
        trid = self.last_message["DHCP6_Advertise"].trid
        if msgtype == 0x2 and trid in self.transaction_history:
            self.updateTransactions(self.last_message)
            print("Unencrypted Advertise obtained!")
            return True
        else:
            return False

    def retrievedUnencryptedReply(self):
        msgtype = self.last_message["DHCP6_Reply"].msgtype
        trid = self.last_message["DHCP6_Reply"].trid
        if msgtype == 0x7 and trid in self.transaction_history:
            self.updateTransactions(self.last_message)
            print("Unencrypted Reply obtained!")
            return True
        else:
            return False