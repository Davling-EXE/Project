from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
class RSAEncryption:
    def __init__(self, key_size=2048):
        self.key = RSA.generate(key_size)
        self.public_key = self.key.publickey()
    def export_public_key(self):
        return self.public_key.export_key()
    def export_private_key(self):
        return self.key.export_key()
    def encrypt_with_public_key(self, data, public_key_bytes):
        recipient_key = RSA.import_key(public_key_bytes)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        return cipher_rsa.encrypt(data)
    def decrypt_with_private_key(self, encrypted_data):
        cipher_rsa = PKCS1_OAEP.new(self.key)
        return cipher_rsa.decrypt(encrypted_data)
class AESEncryption:
    def __init__(self, key=None):
        self.key = key or get_random_bytes(32)
    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(cipher.nonce + tag + ciphertext)
    def decrypt(self, enc_data):
        enc_data = base64.b64decode(enc_data)
        nonce = enc_data[:16]
        tag = enc_data[16:32]
        ciphertext = enc_data[32:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)