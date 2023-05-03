from cryptography.fernet import Fernet

key = b'SToGvxvMfVR7bGbO2-FfCziacjiiyjCeZMMfqyKmFBg=' # Fernet.generate_key()
print(key)
f = Fernet(key)
token = f.encrypt(b"A really secret message. Not for prying eyes.")
print(token)

decrypted_token = f.decrypt(token)
print(decrypted_token)