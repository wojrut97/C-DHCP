import base64
import threading
from netaddr import * 
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from scapy.all import *
from scapy.layers.tls.all import *
import secrets
import netifaces as ni

class Host:
    def __init__(self):
        self.transaction_history = {}
        self.client_port = 546
        self.server_port = 547
        self.handshake_client_port = 1546
        self.handshake_server_port = 1547
        self.handshake_client_port = 1546
        self.handshake_server_port = 1547
        self.servers_multicast_address = "ff02::1:2"
        self.interface = None
        self.last_message = None
        self.ip = None

        #Cryptography
        self.half_key_size = 10
        self.full_key_size = 2 * self.half_key_size
        self.half_key = secrets.token_bytes(10)
        self.full_key = None
        self.salt = b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05"
        self.kdf = None
        self.encryption_key = None
        self.fernet = None



        #Communication
        self.got_certificate = False
        self.got_half_key = False
        self.handshake_message_buffer = []
        self.DHCPv6_message_buffer = []


        #CA
        self.CA_cert_path = "./certificates/ca.crt"
        self.CA_certificate = self.loadCertificate(self.CA_cert_path)
        self.CA_public_key = self.CA_certificate.public_key()

        #Me
        self.certificate_path = None
        self.certificate = None
        self.private_key = None
        
        #Issuer
        self.retrieved_certificate = None
        self.retrieved_public_key = None
        self.retrieved_half_key = None
        self.issuer_ip = None




    def startDHCPv6Listener(self):
        listener = threading.Thread(target=self.DHCPv6Listener, daemon=True)
        listener.start()

    def DHCPv6Listener(self):
        print("DHCPv6 listener ready!")
        while True:
            received = sniff(iface=self.interface_name, filter="dst port " + str(self.receive_port), count=1)
            self.DHCPv6_message_buffer.append(received[0])

    def getIP(self):
        ip = ni.ifaddresses(self.interface_name)[ni.AF_INET6][0]["addr"]
        return ip.split("%")[0]

    def createEncryptionKey(self):
        self.kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.salt,
                    iterations=100000,
                    backend=default_backend())
        self.encryption_key = base64.urlsafe_b64encode(self.kdf.derive(self.full_key))
        self.fernet = Fernet(self.encryption_key)

    def updateTransactions(self, message):
        DHCP6_layer = message.layers()[3]
        trid = message[DHCP6_layer].trid
        if trid not in self.transaction_history:
            self.transaction_history[trid] = [message]
        elif len(self.transaction_history[trid]) == 3:
            del self.transaction_history[trid]
        else:
            self.transaction_history[trid].append(message)

    def loadCertificate(self, path):
        f = open(path)
        content = f.read()
        return x509.load_pem_x509_certificate(content.encode("utf-8"))

    def loadPrivateKey(self, path):
        private_key = None
        with open(path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
        return private_key

    def awaitHandshakeMessage(self):
        while True:
            if self.handshake_message_buffer:
                received = self.handshake_message_buffer.pop()
                break
        self.retrieveMessageData(received)

    def isValidCertificate(self):
        try:
            self.CA_public_key.verify(
                self.retrieved_certificate.signature,
                self.retrieved_certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                self.retrieved_certificate.signature_hash_algorithm
            )
        except InvalidSignature:
            print("Invalid Signature")
            return False
        return True

    def sendCertificate(self):
        layer2 = Ether()
        layer3 = IPv6()
        layer4 = UDP()
        layer3.dst = self.servers_multicast_address
        layer3.src = self.ip
        layer4.sport = self.handshake_receive_port
        layer4.dport = self.handshake_send_port

        cert_message = layer2 / layer3 / layer4 / TLS13Certificate(
            self.certificate.public_bytes(serialization.Encoding.PEM))

        sendp(cert_message, iface=self.interface_name)

    def sendEncryptedHalfKey(self):
        encrypted_half_key = self.retrieved_public_key.encrypt(
            self.half_key, padding.OAEP(
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
        layer4.sport = self.handshake_receive_port
        layer4.dport = self.handshake_send_port

        key_message = layer2 / layer3 / layer4 / encrypted_half_key

        sendp(key_message, iface=self.interface_name)

    def isValidSubject(self):
        if self.retrieved_certificate.subject is not None:
            return True
        else:
            return False

    def awaitDHCPv6Message(self):
        while True:
            if self.DHCPv6_message_buffer:
                received = self.DHCPv6_message_buffer.pop()
                break
        self.last_message = self.decryptDHCPv6Options(received)

    def decryptDHCPv6Options(self, message):
        encrypted_data = bytes(message["Raw"])
        decrypted_data = self.fernet.decrypt(encrypted_data)
        decrypted_message = self.removeRawLayer(message) / decrypted_data
        decrypted_message = decrypted_message.__class__(raw(decrypted_message))
        return decrypted_message

    def removeRawLayer(self, message):
        layer2 = Ether()
        layer3 = IPv6()
        layer4 = UDP()

        layer2.dst = message["Ether"].dst
        layer3.dst = message["IPv6"].dst
        layer4.sport = message["UDP"].sport
        layer4.dport = message["UDP"].dport

        new_message = layer2 / layer3 / layer4
        return new_message


    def retrieveMessageData(self, messages):
        for message in messages:
            if str(message["Raw"])[2:29] == "-----BEGIN CERTIFICATE-----":
                self.retrievePublicKeyAndCertificate(message)
                if self.isValidCertificate():
                    if self.isValidSubject():
                        self.got_certificate = True
                        print("Obtained valid certificate")
            else:
                self.retrieveHalfKey(message)
                self.combineKeyTogether()
                self.createEncryptionKey()
                self.got_half_key = True
                print("Obtained half of the symmetric key")


    def retrievePublicKeyAndCertificate(self, message):
        retrieved_certificate_str = str(message["Raw"])[2:]
        retrieved_certificate_str = retrieved_certificate_str.replace('\\n', '\n')
        self.retrieved_certificate = x509.load_pem_x509_certificate(retrieved_certificate_str.encode("utf-8"))
        self.retrieved_public_key = self.retrieved_certificate.public_key()

    def retrieveHalfKey(self, message):
        hashed_key = bytes(message["Raw"])
        self.retrieved_half_key = self.private_key.decrypt(
            hashed_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
            )

    def createDUID(self):
        return "00030001" + str(EUI(self.interface.MAC)).replace("-","")

####Unencrypted DHCPv6 part####

    def awaitUnencryptedDHCPv6Message(self):
        while True:
            if self.DHCPv6_message_buffer:
                received = self.DHCPv6_message_buffer.pop()
                break
        self.last_message = received
