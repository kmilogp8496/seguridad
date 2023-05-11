from Crypto.Cipher import AES
import requests
import random
import json

DEVICE_ID = "client"
SERVER_ID = "server"

# key = b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw"
# cipher = AES.new(key, AES.MODE_EAX)
# ciphertext, tag = cipher.encrypt_and_digest(data)


def aes_decrypt(data):
    nonce, tag, ciphertext = data.split(b":")

    key = b'\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw'
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# data = b':'.join([cipher.nonce, tag, ciphertext])

# BASE_ADDRESS = '127.0.0.1:5000'

# QUERY_URI = f'http://{BASE_ADDRESS}/aes'

random_number = random.randint(0, 1000)

get_key_data = {"id": DEVICE_ID, "random": random_number}

r = requests.post(
    "http://localhost:5000/generate_key", data=json.dumps(get_key_data), timeout=10000
)

json_data = json.loads(r.text)

kas = aes_decrypt(json_data)


if kas["idB"] == SERVER_ID and kas["randomA"] == random_number:
    kab = kas["key"]
    print(kab)

print("NO ENTRAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
