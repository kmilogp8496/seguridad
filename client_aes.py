"""Demo for AES encryption"""
import random
import json
from base64 import b64decode
from Seguridad.clients import ServerClient
from Seguridad.seguridad import AESDemo, ChaChaDemo

DEVICE_ID = "client"
SERVER_ID = "server"
GENERATOR_SHARED_KEY = b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw"

random_number = random.randint(0, 1000)

get_key_data = json.dumps({"id": DEVICE_ID, "random": random_number})

client = ServerClient(DEVICE_ID)

response = client.generate_key(get_key_data)

decoded_text = b64decode(response.text)

decrypter = AESDemo(GENERATOR_SHARED_KEY)

kas = json.loads(decrypter.decrypt(decoded_text))

if kas["idB"] == SERVER_ID and kas["randomA"] == random_number:
    kab: str = kas["key"]

chacha = ChaChaDemo(b64decode(kab))

r = client.chacha(chacha.encrypt("Hello Chacha".encode()))

print(r.text)
