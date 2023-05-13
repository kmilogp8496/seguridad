"""Summary
    Demo classes for AES, Fernet and ChaCha20 encryption
"""
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from .encryption_demo import EncryptionDemo
from cryptography.fernet import Fernet


class AESDemo(EncryptionDemo):
    """Summary

    Attributes:
        key (bytes): Key to be used for encryption
        mode (TYPE): Decryption mode for AES from Crypto.Cipher
    """

    def __init__(self, key: bytes, mode=AES.MODE_EAX):
        super().__init__(key)
        self.mode = mode

    def encrypt(self, data: bytes):
        cipher = AES.new(self.key, self.mode)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        data = b"::".join([cipher.nonce, tag, ciphertext])
        return data

    def decrypt(self, data) -> str:
        nonce, tag, ciphertext = data.split(b"::")
        cipher = AES.new(self.key, self.mode, nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()


class ChaChaDemo(EncryptionDemo):
    """Summary

    Attributes:
        key (bytes): Key to be used for encryption
    """

    def encrypt(self, data: bytes) -> str:
        cipher = ChaCha20.new(key=self.key)
        ciphertext = cipher.encrypt(data)
        nonce = b64encode(cipher.nonce).decode()
        decoded_cipher_text = b64encode(ciphertext).decode()
        return json.dumps({"nonce": nonce, "ciphertext": decoded_cipher_text})

    def decrypt(self, data: str) -> str:
        b64 = json.loads(data)
        nonce = b64decode(b64["nonce"])
        cipher_text = b64decode(b64["ciphertext"])
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        plaintext = cipher.decrypt(cipher_text)
        return plaintext.decode()


class FernetDemo(EncryptionDemo):
    """Summary

    Attributes:
        key (bytes): Key to be used for encryption
    """

    def encrypt(self, data: bytes) -> bytes:
        fernet = Fernet(self.key)
        token = fernet.encrypt(data)
        return token

    def decrypt(self, data: str) -> str:
        fernet = Fernet(self.key)
        return fernet.decrypt(data).decode()
