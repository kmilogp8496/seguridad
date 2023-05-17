"""Demo for AES encryption"""
import random
import json
from time import sleep
from base64 import b64decode
from Seguridad.clients import ServerClient
from Seguridad.seguridad import AESDemo, ChaChaDemo, FernetDemo

DEVICE_ID = "client"
SERVER_ID = "server"
GENERATOR_SHARED_KEY = b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw"


for i in range(1000):
    random_number = random.randint(0, 1000)

    get_key_data = json.dumps({"id": DEVICE_ID, "random": random_number})
    client = ServerClient(DEVICE_ID)
    response = client.generate_key(get_key_data)

    decoded_text = b64decode(response.text)
    encrypter = AESDemo(GENERATOR_SHARED_KEY)
    kas = json.loads(encrypter.decrypt(decoded_text))

    if kas["idB"] == SERVER_ID and kas["randomA"] == random_number:
        kab: str = kas["key"]

    new_key = b64decode(kab)
    data = json.dumps({"temperature": random.randint(0, 30)})

    chacha = ChaChaDemo(new_key)
    r = client.chacha(chacha.encrypt(data.encode()))
    print("ChaCha response: " + r.text)

    fernet = FernetDemo(kab)
    r = client.fernet(fernet.encrypt(data.encode()))
    print("Fernet response: " + r.text)

    aes = AESDemo(new_key)
    r = client.fernet(fernet.encrypt(data.encode()))
    print("AES response: " + r.text)

    sleep(2)
