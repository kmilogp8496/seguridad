import requests
from cryptography.fernet import Fernet

key = b'SToGvxvMfVR7bGbO2-FfCziacjiiyjCeZMMfqyKmFBg='
f = Fernet(key)

BASE_ADDRESS = '127.0.0.1:5000'

QUERY_URI = f'http://{BASE_ADDRESS}/fernen'

data = b'{"temperature": 20}'

temperature = f.encrypt(data)

r = requests.post(QUERY_URI, data=temperature, timeout=10000)

print(r.text)