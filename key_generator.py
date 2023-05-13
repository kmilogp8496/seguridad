from flask import Flask, request
from Crypto.Random import get_random_bytes
import json
from base64 import b64encode
from Seguridad.app import IP_ADDRESS, KEY_GENERATOR_PORT
from Seguridad.seguridad import AESDemo

app = Flask(__name__)

keys = {
    "server": b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xeew",
    "client": b"\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw",
}


@app.route("/generate/", methods=["POST"])
def generate_keys():
    """Summary
    Generate keys for client A and B

    Returns:
        Keys for client A and B in base64 encoded format
    """
    data = request.get_data()
    json_data = json.loads(data)
    key_a = keys[json_data["idA"]]
    key_b = keys[json_data["idB"]]
    generated_key = get_random_bytes(32)
    print(generated_key)

    ka_data = {
        "key": b64encode(generated_key).decode(),
        "idB": json_data["idB"],
        "randomA": json_data["randomA"],
    }
    kb_data = {
        "key": b64encode(generated_key).decode(),
        "idA": json_data["idA"],
        "randomB": json_data["randomB"],
    }

    encrypter_a = AESDemo(key_a)
    encrypter_b = AESDemo(key_b)

    return {
        "kas": b64encode(
            encrypter_a.encrypt(json.dumps(ka_data).encode())
        ).decode(),
        "kbs": b64encode(
            encrypter_b.encrypt(json.dumps(kb_data).encode())
        ).decode(),
    }


app.run(host=IP_ADDRESS, port=KEY_GENERATOR_PORT)
