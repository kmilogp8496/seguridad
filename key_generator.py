from flask import Flask, request
from Crypto.Cipher import AES

app = Flask(__name__)

keys = {
    0: b'\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xeew',
    1: b'\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw',
}

@app.route('/generate/<device_id>', methods=['POST'])
def read_sensors_aes(device_id):
    data = request.get_data()

    nonce, tag, ciphertext = data.split(b':')

    key = b'\xad\xa3h\xf0\xf5\xdb\x82\xee;V\x189#-\xaaw'
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    return {"message": f'{data}'}, 200

app.run(host="0.0.0.0", port="5000")
