import json
import random
from base64 import b64decode
import requests
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import AES
from flask import Flask, request
from cryptography.fernet import Fernet

app = Flask(__name__)

keys = {}

DEVICE_ID = "server"


def aes_decrypt(data):
    nonce, tag, ciphertext = data.split(b":")

    key = b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xeew"
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


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


@app.route("/aes", methods=["POST"])
def read_sensors_aes():
    data = request.get_data()

    decrypted_data = aes_decrypt(data)

    return {"message": f"{decrypted_data}"}, 200


@app.route("/chacha", methods=["POST"])
def read_sensors_chacha():
    key = b"\xc0\xbd\xfbS\x92\x9e\xa4\x0e\xf4\xc6\xd0|\x12j\x96\xe9\x11A\xf6\x1c\x9f\x88.\xb0\x1d\xe7\x88-\x13\x88\xb9\xd8"

    try:
        b64 = json.loads(request.get_data())
        nonce = b64decode(b64["nonce"])
        cipher_text = b64decode(b64["ciphertext"])
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(cipher_text)
        print("The message was " + f"{plaintext}")
    except (ValueError, KeyError):
        print("Incorrect decryption")

    return {"message": f"{plaintext}"}, 200


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
    response = requests.post(
        "http://localhost:5001/generate/", data=json.dumps(new_data), timeout=10000
    )
    encrypted_keys = json.loads(response.text)
    print(b64decode(encrypted_keys["kbs"]))
    kbs = aes_decrypt(b64decode(encrypted_keys["kbs"]))

    if kbs["idA"] == id_device and kbs["randomB"] == random_number:
        keys.update(dict(id_device, kbs["key"]))
        print(keys)
        return encrypted_keys["kas"]

    return "Error generating keys"


app.run(host="0.0.0.0", port="5000")
