import base64
from netaddr import * 
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.extensions import TLSFeature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from scapy.all import *
from scapy.layers.tls.all import *
import config
import string
import random
import secrets
import netifaces as ni

class Host:
    def __init__(self):
        self.transaction_history = {}
        self.client_port = 546
        self.server_port = 547
        self.ssl_port = 443
        self.servers_multicast_address = "ff02::1:2"
        self.interface = None
        self.last_message = None
        self.ip = self.getIP()
        print("My ip: ", self.ip)

        #Cryptography
        self.half_key_size = 10
        self.full_key_size = 2 * self.half_key_size
        self.half_key = secrets.token_bytes(10)
        self.full_key = None
        self.salt = b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05"
        self.kdf = None
        self.encryption_key = None
        self.fernet = None


        #CA
        self.CA_cert_path = "./certificates/ca.crt"
        self.CA_certificate = self.loadCertificate(self.CA_cert_path)
        self.CA_public_key = self.CA_certificate.public_key()

        #Me
        self.certificate_path = None
        self.certificate = None
        self.private_key = None
        
        #Issuer
        self.retrieved_certificate_str = None
        self.retrieved_certificate = None
        self.retrieved_public_key = None
        self.retrieved_half_key = None
        self.issuer_ip = None

    def getIP(self):
        ip = ni.ifaddresses("enp0s8")[ni.AF_INET6][0]["addr"]
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

    def verifyCertificate(self):
        # Verify signature
        try:
            self.CA_public_key.verify(
                self.retrieved_certificate.signature,
                self.retrieved_certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                self.retrieved_certificate.signature_hash_algorithm
            )
        except InvalidSignature:
            print("Invalid Signature")
            return 1
        # Verify subject
        if self.retrieved_certificate.subject is not None:
            return 0
        else:
            return 2

    def awaitDHCPv6Message(self, port):
        received = sniff(iface="enp0s8", filter="dst port " + str(port), count=1)
        self.last_message = self.decryptDHCPv6Options(received[0])

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
                print("Reterieved certificate ")
            elif len(message["Raw"]) < 20:
                print("Retrieved raw half-key")
                self.retrieveHalfKey(message)
            else:
                print("Retrieved encrypted half-key")
                self.retrieveEncryptedHalfKey(message)


    def retrievePublicKeyAndCertificate(self, message):
        self.retrieved_certificate_str = str(message["Raw"])[2:]
        self.retrieved_certificate_str = self.retrieved_certificate_str.replace('\\n', '\n')
        self.retrieved_certificate = x509.load_pem_x509_certificate(self.retrieved_certificate_str.encode("utf-8"))
        self.retrieved_public_key = self.retrieved_certificate.public_key()

    def retrieveEncryptedHalfKey(self, message):
        hashed_key = bytes(message["Raw"])
        print("Typ:", type(hashed_key), "value:", hashed_key, "Len:", len(hashed_key))
        print("Typ:", type(self.private_key), "value:", hashed_key, "Len:", len(hashed_key))
        self.retrieved_half_key = self.private_key.decrypt(
            hashed_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
            )

    def retrieveHalfKey(self, message):
        self.retrieved_half_key = bytes(message["Raw"])

    def createDUID(self):
        return "00030001" + str(EUI(self.MAC)).replace("-","")
