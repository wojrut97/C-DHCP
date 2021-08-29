from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
f = open("./ca.crt", "r")
content = f.read()
print(content)

cert = x509.load_pem_x509_certificate(content.encode("utf-8"))
print(cert.public_key)