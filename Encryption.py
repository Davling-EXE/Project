from typing import Optional
# Simple RSA and AES encryption utilities
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

class RSAEncryption:
    # RSA encryption for key exchange
    def __init__(self) -> None:
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
    def export_public_key(self) -> bytes:
        # Export public key bytes
        return self.public_key.export_key()
    def encrypt_with_public_key(self, data: bytes, public_key_bytes: bytes) -> bytes:
        # Encrypt data with a public key
        pub_key = RSA.import_key(public_key_bytes)
        cipher = PKCS1_OAEP.new(pub_key)
        return cipher.encrypt(data)
    def decrypt_with_private_key(self, encrypted_data: bytes) -> bytes:
        # Decrypt data with private key
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.decrypt(encrypted_data)

class AESEncryption:
    # AES encryption for messages
    def __init__(self, key: Optional[bytes] = None) -> None:
        self.key: bytes = key if key else get_random_bytes(32)
    def encrypt(self, data: bytes) -> bytes:
        # Encrypt data with AES (GCM)
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext
    def decrypt(self, encrypted_data: bytes) -> bytes:
        # Decrypt AES-encrypted data
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)