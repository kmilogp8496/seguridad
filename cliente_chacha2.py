import json
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import requests

BASE_ADDRESS = '127.0.0.1:5000'

QUERY_URI = f'http://{BASE_ADDRESS}/chacha'

plaintext = b'{"temperature": 10}'
key = b'\xc0\xbd\xfbS\x92\x9e\xa4\x0e\xf4\xc6\xd0|\x12j\x96\xe9\x11A\xf6\x1c\x9f\x88.\xb0\x1d\xe7\x88-\x13\x88\xb9\xd8'
cipher = ChaCha20.new(key=key)
ciphertext = cipher.encrypt(plaintext)

nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ciphertext).decode('utf-8')
result = json.dumps({'nonce':nonce, 'ciphertext':ct})

r = requests.post(QUERY_URI, data=result, timeout=10000)
