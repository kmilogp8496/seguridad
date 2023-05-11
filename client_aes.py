from Crypto.Cipher import AES
import requests
import json

data = b'{"temperature": 20}'

print(data)
print(json.dumps({"temperature": 20}).encode('utf-8'))

key = b'\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw'

cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)


data = b':'.join([cipher.nonce, tag, ciphertext])


BASE_ADDRESS = '127.0.0.1:5000'

QUERY_URI = f'http://{BASE_ADDRESS}/aes'

r = requests.post(QUERY_URI, data=data, timeout=10000)
