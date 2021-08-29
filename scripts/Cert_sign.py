from cryptography import x509
import cryptography
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import ssl
import pprint

#####################################################

ca_crt_path = "./certificates/ca.crt"
client_crt_path = "./certificates/client.crt"
hacker_crt_path = "./certificates/hacker.crt"
client_private_key_path = "./keys/client.key"

f_ca = open(ca_crt_path)
ca_content = f_ca.read()
ca_certificate = x509.load_pem_x509_certificate(ca_content.encode("utf-8"))
ca_public_key = ca_certificate.public_key()

f_client = open(client_crt_path)
client_content = f_client.read()
client_certificate = x509.load_pem_x509_certificate(client_content.encode("utf-8"))

# client_private_key = open(client_private_key_path)
# private_key_content = client_private_key.read()
# print(private_key_content)
# private_key = serialization.load_pem_private_key(client_private_key.read(), password=None)
client_private_key = None

with open(client_private_key_path, "rb") as key_file:
    client_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

pprint.pprint(ca_public_key)
ca_public_key.verify(
    client_certificate.signature,
    client_certificate.tbs_certificate_bytes,
    padding.PKCS1v15(),
    client_certificate.signature_hash_algorithm
)

client_public_key = client_certificate.public_key()

import secrets
message = secrets.token_bytes(10)
crypted_message = client_public_key.encrypt(message, 
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

print("smiec: ", crypted_message)
print("dlugosc zaszyfrowanej: ", len(crypted_message))
print("Typek: ", type(crypted_message))

decrypted_message = client_private_key.decrypt(
    crypted_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None)
    )

if decrypted_message == message:
    print("Sukces!")
else:
    print("Zjebalo sie")
    print(message)
    print(decrypted_message)

# cert_dict = ssl._ssl._test_decode_cert(client_crt_path)
# ca_dict = ssl._ssl._test_decode_cert(ca_crt_path)
# pprint.pprint(cert_dict)
# pprint.pprint(ca_dict)S