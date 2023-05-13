"""Summary
Abstract class for encryption
"""


class EncryptionDemo:
    """Summary
    Abstract class for encryption
    """

    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, data: bytes) -> str:
        """Summary

        Args:
            data (bytes): Data to be encrypted

        Raises:
            NotImplementedError: Subclass must implement abstract method

        Returns:
            str: Encrypted data
        """
        raise NotImplementedError("Subclass must implement abstract method")

    def decrypt(self, data: bytes, nonce: bytes) -> str:
        """Summary

        Args:
            data (bytes): Data to be decrypted

        Raises:
            NotImplementedError: Subclass must implement abstract method

        Returns:
            str: Decrypted data
        """

        raise NotImplementedError("Subclass must implement abstract method")
