"""Summary
Abstract class for encryption
"""
from abc import ABC, abstractmethod

class EncryptionDemo(ABC):
    """Summary
    Abstract class for encryption
    """
    def __init__(self, key: bytes):
        self.key = key

    @abstractmethod
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
    
    @abstractmethod
    def decrypt(self, data: bytes) -> str:
        """Summary

        Args:
            data (bytes): Data to be decrypted

        Raises:
            NotImplementedError: Subclass must implement abstract method

        Returns:
            str: Decrypted data
        """

        raise NotImplementedError("Subclass must implement abstract method")
