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


def encrypt(data, client_id):
    """Summary

    Args:
        data (bytes): Data to be encrypted
        client_id (str): Client ID
    Returns:
        bytes: Encrypted data
    """
    key = keys[client_id]
    cipher = AES.new(key, AES.MODE_EAX)
    cipher_text, tag = cipher.encrypt_and_digest(data)
    return b":".join([cipher.nonce, tag, cipher_text])


@app.route("/generate/", methods=["POST"])
def generate_keys():
    """Summary
    Generate keys for client A and B

    Returns:
        Keys for client A and B in base64 encoded format
    """
    data = request.get_data()
    json_data = json.loads(data)

    generated_key = get_random_bytes(16)

    ka_data = {
        "key": str(b64encode(generated_key).decode("utf-8")),
        "idB": json_data["idB"],
        "randomA": json_data["randomA"],
    }
    kb_data = {
        "key": str(b64encode(generated_key).decode("utf-8")),
        "idA": json_data["idA"],
        "randomB": json_data["randomB"],
    }

    return {
        "kas": str(
            b64encode(
                encrypt(json.dumps(ka_data).encode("utf-8"), json_data["idA"])
            ).decode("utf-8")
        ),
        "kbs": str(
            b64encode(
                encrypt(json.dumps(kb_data).encode("utf-8"), json_data["idB"])
            ).decode("utf-8")
        ),
    }


app.run(host="0.0.0.0", port="5001")
