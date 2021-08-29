from scapy.all import *
from scapy.layers.tls.handshake import TLS13Certificate, TLS13ClientHello, TLSCertificate, TLSClientHello
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
f = open("./ca.crt", "r")
content = f.read()
print(content)

cert = x509.load_pem_x509_certificate(content.encode("utf-8"))
print(cert.public_key)

load_layer('tls')

l2 = Ether()
l3 = IPv6()
l4 = TCP()
l2.dst = "ff:ff:ff:ff:ff:ab"
l3.dst = "ff02::1:2"
l4.sport = 443
l4.dport = 443

message = l2 / l3 / l4 / TLS13Certificate(cert.public_bytes(serialization.Encoding.PEM)) / TLS13Certificate(cert.public_bytes(serialization.Encoding.PEM))

sendp(message, iface="enp0s8")