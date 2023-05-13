"""App configuration module
"""
import os
from dotenv import load_dotenv

load_dotenv()

IP_ADDRESS = os.getenv("IP_ADDRESS")
SERVER_PORT = os.getenv("SERVER_PORT")
KEY_GENERATOR_PORT = os.getenv("KEY_GENERATOR_PORT")
BASE_URL_SERVER = os.getenv("BASE_URL_SERVER")
BASE_URL_KEY_GENERATOR = os.getenv("BASE_URL_KEY_GENERATOR")
