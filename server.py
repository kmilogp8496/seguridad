import json
import random
from base64 import b64decode
import requests
from Crypto.Cipher import ChaCha20
from flask import Flask, request
from cryptography.fernet import Fernet
from Seguridad.app import IP_ADDRESS, SERVER_PORT
from Seguridad.seguridad import AESDemo
from Seguridad.clients import KeyGeneratorClient

app = Flask(__name__)

keys = {}

DEVICE_ID = "server"

GENERATOR_SHARED_KEY = b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xeew"


@app.route("/fernen", methods=["POST"])
def read_sensors_fernet():
    """Summary
    Decrypts the data sent by the client using Fernet encryption

    Returns:
        dict: Decrypted data
    """
    key = b"SToGvxvMfVR7bGbO2-FfCziacjiiyjCeZMMfqyKmFBg="
    f = Fernet(key)
    data = request.get_data()
    decrypted_token = f.decrypt(data)

    return {"message": f"{decrypted_token}"}, 200


@app.route("/aes/<device_id>", methods=["POST"])
def read_sensors_aes(device_id: str):
    data = request.get_data()
    decrypter = AESDemo(keys[device_id])
    decrypted_data = decrypter.decrypt(data)

    return {"message": decrypted_data.encode()}, 200


@app.route("/chacha/<device_id>", methods=["POST"])
def read_sensors_chacha(device_id: str):
    key = b64decode(keys[device_id])

    try:
        b64 = json.loads(request.get_data())
        nonce = b64decode(b64["nonce"])
        cipher_text = b64decode(b64["ciphertext"])
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(cipher_text)
    except (ValueError, KeyError):
        print("Incorrect decryption")

    return {"message": plaintext.decode()}, 200


@app.route("/generate_key", methods=["POST"])
def generate_key():
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

    decrypter = AESDemo(GENERATOR_SHARED_KEY)

    kbs = json.loads(decrypter.decrypt(b64decode(encrypted_keys["kbs"])))

    if kbs["idA"] == id_device and kbs["randomB"] == random_number:
        keys.update({f"{id_device}": kbs["key"]})
        return encrypted_keys["kas"]

    return "Error generating keys"


app.run(host=IP_ADDRESS, port=SERVER_PORT)
