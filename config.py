# config.py

import os
import mysql.connector
import base64
from dotenv import load_dotenv

load_dotenv()

# Database Config
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "secure_health_db")

def get_db_conn():
    return mysql.connector.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, database=DB_NAME
    )

def load_keys():
    """Loads AES and HMAC keys from .env"""
    aes_b64 = os.getenv("AES_KEY_B64")
    hmac_b64 = os.getenv("HMAC_KEY_B64")
    
    if not aes_b64 or not hmac_b64:
        raise ValueError("Keys not found in .env")
        
    return base64.b64decode(aes_b64), base64.b64decode(hmac_b64)