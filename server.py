from flask import Flask, request
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
import json
from base64 import b64decode
from Crypto.Cipher import ChaCha20

app = Flask(__name__)

key = b'SToGvxvMfVR7bGbO2-FfCziacjiiyjCeZMMfqyKmFBg='
f = Fernet(key)

@app.route('/fernen', methods=['POST'])
def read_sensors_fernet():
    data = request.get_data()
    print(data)
    decrypted_token = f.decrypt(data)
    print(decrypted_token)

    return {"message": f'{decrypted_token}'}, 200

@app.route('/aes', methods=['POST'])
def read_sensors_aes():
    data = request.get_data()

    nonce, tag, ciphertext = data.split(b':')

    key = b'\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw'
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    return {"message": f'{data}'}, 200

@app.route('/chacha', methods=['POST'])
def read_sensors_chacha():
    key = b'\xc0\xbd\xfbS\x92\x9e\xa4\x0e\xf4\xc6\xd0|\x12j\x96\xe9\x11A\xf6\x1c\x9f\x88.\xb0\x1d\xe7\x88-\x13\x88\xb9\xd8'
    
    try:
        b64 = json.loads(request.get_data())
        nonce = b64decode(b64['nonce'])
        ciphertext = b64decode(b64['ciphertext'])
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        print("The message was " + f'{plaintext}')
    except (ValueError, KeyError):
        print("Incorrect decryption")

    return {"message": f'{plaintext}'}, 200
    

app.run(host="0.0.0.0", port="5000")
