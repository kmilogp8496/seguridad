from flask import Flask, request
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json
from base64 import b64encode

app = Flask(__name__)

keys = {
    "server": b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xeew",
    "client": b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw",
}

def encrypt(data, clientId):
    key = keys[clientId]
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return b":".join([cipher.nonce, tag, ciphertext])

@app.route("/generate/", methods=["POST"])
def read_sensors_aes():
    data = request.get_data()
    jsonData = json.loads(data)

    generatedKey = get_random_bytes(16)

    kaData = {
        "key": str(b64encode(generatedKey).decode("utf-8")),
        "idB": jsonData["idB"],
        "randomA": jsonData["randomA"],
    }
    kbData = {
        "key": str(b64encode(generatedKey).decode("utf-8")),
        "idA": jsonData["idA"],
        "randomB": jsonData["randomB"],
    }

    return {
        "kas": str(b64encode(encrypt(json.dumps(kaData).encode("utf-8"), jsonData["idA"])).decode("utf-8")),
        "kbs": str(b64encode(encrypt(json.dumps(kbData).encode("utf-8"), jsonData["idB"])).decode("utf-8")),
    }


app.run(host="0.0.0.0", port="5001")
