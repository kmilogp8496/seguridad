from Crypto.Cipher import AES
import requests

data = b'{"temperature": 20}'

key = b'\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw'

cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)


data = b':'.join([cipher.nonce, tag, ciphertext])


BASE_ADDRESS = '127.0.0.1:5000'

QUERY_URI = f'http://{BASE_ADDRESS}/aes'

r = requests.post(QUERY_URI, data=data, timeout=10000)

print(r.text)

# file_in = open("encrypted.bin", "rb")
# nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
# file_in.close()

# cipher = AES.new(key, AES.MODE_EAX, nonce)
# data = cipher.decrypt_and_verify(ciphertext, tag)
# print(data)