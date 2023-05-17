"""Summary
Client for the servers
"""
from requests import post, Response
from .app import BASE_URL_SERVER, BASE_URL_KEY_GENERATOR


class ServerClient:
    """Client for connecting to the server"""

    def __init__(self, device_id: str, uri=BASE_URL_SERVER):
        self.uri = uri
        self.device_id = device_id

    def chacha(self, data: str) -> Response:
        """Chacha client call

        Args:
            data (str): encrypted data for chacha decryption
        """
        return post(f"{self.uri}/chacha/{self.device_id}", data=data, timeout=10000)

    def fernet(self, data: bytes) -> Response:
        """Fernet client call

        Args:
            data (str): encrypted data for fernet decryption
        """
        return post(f"{self.uri}/fernet/{self.device_id}", data=data, timeout=10000)

    def aes(self, data: bytes) -> Response:
        """AES client call

        Args:
            data (str): encrypted data for aes decryption
        """
        return post(f"{self.uri}/aes/{self.device_id}", data=data, timeout=10000)

    def generate_key(self, data: str) -> Response:
        """Generate key for encryption

        Args:
            data (dict): data for key generation
        """
        return post(f"{self.uri}/generate_key", data=data, timeout=10000)


class KeyGeneratorClient:
    """Client for connecting to the key generator"""

    def __init__(self, uri=BASE_URL_KEY_GENERATOR):
        self.uri = uri

    def generate(self, data: str) -> Response:
        """Generate keys for client A and B"""
        return post(f"{self.uri}/generate/", data=data, timeout=10000)
