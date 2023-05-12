import random
import json
from base64 import b64decode
import requests
from Crypto.Cipher import AES

DEVICE_ID = "client"
SERVER_ID = "server"

# key = b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw"
# cipher = AES.new(key, AES.MODE_EAX)
# ciphertext, tag = cipher.encrypt_and_digest(data)


def aes_decrypt(data):
    nonce, tag, ciphertext = data.split(b":")

    key = b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw"
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


random_number = random.randint(0, 1000)

get_key_data = {"id": DEVICE_ID, "random": random_number}

response = requests.post(
    "http://localhost:5000/generate_key", data=json.dumps(get_key_data), timeout=10000
)

# json_data = r.json()


decoded_text = b64decode(response.text)

kas = json.loads(aes_decrypt(decoded_text).decode("utf-8"))

print(kas)

if kas["idB"] == SERVER_ID and kas["randomA"] == random_number:
    kab = kas["key"]
    print(kab)

