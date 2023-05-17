"""Benchmarking encryption algorithms
"""

import timeit
from base64 import b64encode
from Crypto.Cipher import ChaCha20, AES
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet

DATA = b"Hello World"
chacha_key = get_random_bytes(32)
fernet_key = b64encode(get_random_bytes(32))


def chacha():
    """Summary
    ChaCha20 encryption and decryption
    """
    cipher = ChaCha20.new(key=chacha_key)
    ciphertext = cipher.encrypt(DATA)
    decrypt_cipher = ChaCha20.new(key=chacha_key, nonce=cipher.nonce)
    decrypt_cipher.decrypt(ciphertext)


def fernet():
    """Summary
    Fernet encryption and decryption
    """
    f = Fernet(fernet_key)
    token = f.encrypt(DATA)
    f.decrypt(token)


def aes():
    """Summary
    AES encryption and decryption
    """
    cipher = AES.new(chacha_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(DATA)
    decrypt_cipher = AES.new(chacha_key, AES.MODE_EAX, cipher.nonce)
    decrypt_cipher.decrypt_and_verify(ciphertext, tag)


executions = [100, 1000, 10000]


def format_time(time: float) -> str:
    """Summary

    Args:
        time (float): Time data to round

    Returns:
        str: time rounded in ms
    """
    return round(time * 1000, 2)


print("Encryption Benchmarking")
print("---------------------------------------------------------------")
print(f"| {f'Rows':^8} | {f'ChaCha':^14} | {f'Fernet':^14} | {f'AES':^14} |")
print("|----------|----------------|----------------|----------------|")
for execution in executions:
    chacha_time = timeit.timeit(chacha, number=execution)
    fernet_time = timeit.timeit(fernet, number=execution)
    aes_time = timeit.timeit(aes, number=execution)
    print(f"| {execution:>8} | {format_time(chacha_time):>11} ms | {format_time(fernet_time):>11} ms | {format_time(aes_time):>11} ms |")

print("---------------------------------------------------------------")
