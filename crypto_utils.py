# crypto_utils.py

import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Password Hashing (PBKDF2)
def hash_password(password):
    salt = get_random_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt, pwd_hash

# Verify PBKDF2 hash using constant-time comparison to mitigate timing attacks.
def verify_password(stored_salt, stored_hash, input_password):
    check_hash = hashlib.pbkdf2_hmac('sha256', input_password.encode(), stored_salt, 100000)
    # Use constant-time comparison to avoid timing attacks
    return hmac.compare_digest(check_hash, stored_hash)

# AES-GCM Encryption (Confidentiality)
def encrypt_val(key, value):
    """Encrypts a value (int or str) -> returns (ciphertext, nonce, tag)"""
    cipher = AES.new(key, AES.MODE_GCM)
    data = str(value).encode('utf-8')
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, cipher.nonce, tag

def decrypt_val(key, ciphertext, nonce, tag, value_type=str):
    """Decrypts -> returns value cast to type (int/str)"""
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return value_type(data.decode('utf-8'))
    except ValueError:
        return "[INTEGRITY FAIL]"

# HMAC & Canonicalization (Row Integrity)
def get_row_bytes(first, last, weight, height, history):
    """Creates a standard byte string from row data for hashing"""
    s = f"{first}|{last}|{weight}|{height}|{history}"
    return s.encode('utf-8')

def compute_hmac(key, data_bytes):
    return hmac.new(key, data_bytes, hashlib.sha256).digest()