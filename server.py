import json
import random
from base64 import b64decode
from flask import Flask, request
from Seguridad.app import IP_ADDRESS, SERVER_PORT
from Seguridad.seguridad import AESDemo, ChaChaDemo, FernetDemo
from Seguridad.clients import KeyGeneratorClient

app = Flask(__name__)

keys = {}

DEVICE_ID = "server"

GENERATOR_SHARED_KEY = b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xeew"


@app.route("/fernet/<device_id>", methods=["POST"])
def read_sensors_fernet(device_id: str):
    """Summary
    Decrypts the data sent by the client using Fernet encryption

    Returns:
        dict: Decrypted message
    """
    fernet = FernetDemo(keys[device_id])
    data = request.get_data()
    decrypted_token = fernet.decrypt(data)

    return {"message": decrypted_token}


@app.route("/aes/<device_id>", methods=["POST"])
def read_sensors_aes(device_id: str):
    """Summary
    Decrypts the data sent by the client using AES encryption

    Args:
        device_id (str): Device ID

    Returns:
        dict: Decrypted message
    """
    data = request.get_data()
    encrypter = AESDemo(keys[device_id])
    decrypted_data = encrypter.decrypt(data)

    return {"message": decrypted_data}


@app.route("/chacha/<device_id>", methods=["POST"])
def read_sensors_chacha(device_id: str):
    """Summary
    Decrypts the data sent by the client using ChaCha20 encryption

    Args:
        device_id (str): Device ID

    Returns:
        dict: Decrypted message
    """
    key = b64decode(keys[device_id])
    encrypter = ChaChaDemo(key)
    b64 = json.loads(request.get_data())
    nonce = b64decode(b64["nonce"])
    cipher_text = b64decode(b64["ciphertext"])
    plaintext = encrypter.decrypt(cipher_text, nonce)
    return {"message": plaintext}


@app.route("/generate_key", methods=["POST"])
def generate_key():
    """Summary
    Generates the keys for communication
    
    Returns:
        str: Encrypted keys for communication
    """
    data = request.get_data()
    json_data = json.loads(data)
    id_device = json_data["id"]
    random_number_device = json_data["random"]
    random_number = random.randint(0, 1000)
    new_data = {
        "idA": id_device,
        "randomA": random_number_device,
        "idB": DEVICE_ID,
        "randomB": random_number,
    }

    client = KeyGeneratorClient()

    response = client.generate(json.dumps(new_data))
    encrypted_keys = response.json()

    encrypter = AESDemo(GENERATOR_SHARED_KEY)

    kbs = json.loads(encrypter.decrypt(b64decode(encrypted_keys["kbs"])))

    if kbs["idA"] == id_device and kbs["randomB"] == random_number:
        keys.update({f"{id_device}": kbs["key"]})
        return encrypted_keys["kas"]

    return "Error generating keys"


app.run(host=IP_ADDRESS, port=SERVER_PORT)
