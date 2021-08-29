import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import cryptography
from cryptography.fernet import Fernet

password_provided = 'CDPTBEPOCVBLPXWZCHDN'
password = password_provided.encode()

salt = b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05"

kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend())

key = base64.urlsafe_b64encode(kdf.derive(password))
print(key)

data = b"MaszTuIpIniePierdolGlupot"

fernet = Fernet(key)
encrpyted = fernet.encrypt(data)
print(encrpyted)

decrypted = fernet.decrypt(encrpyted)

print(decrypted)