import requests
import json
from base64 import b64encode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

BASE_ADDRESS = '127.0.0.1:5000'

QUERY_URI = f'http://{BASE_ADDRESS}/chacha'

data = b'{"temperature": 20}'


plaintext = b'{"temperature": 20}'
key = b'\xc0\xbd\xfbS\x92\x9e\xa4\x0e\xf4\xc6\xd0|\x12j\x96\xe9\x11A\xf6\x1c\x9f\x88.\xb0\x1d\xe7\x88-\x13\x88\xb9\xd8'

cipher = ChaCha20.new(key=key)
ciphertext = cipher.encrypt(plaintext)
nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ciphertext).decode('utf-8')
data = b':'.join([nonce, ct])
print(data)

# r = requests.post(QUERY_URI, data=data, timeout=10000)
r = requests.post('http://localhost:5000/', data='{"temperature": 20}', timeout=10000)

print(r.text)
