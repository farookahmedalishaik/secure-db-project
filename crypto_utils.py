# crypto_utils.py

'''
crypto_utils.py acts necessary for core mathematical functions for security.

1) hash_password/verify_password (Authentication): Uses PBKDF2-SHA256 with Salting (100k iterations) to secure credentials.
It employs Constant-Time Comparison (hmac.compare_digest) to prevent timing attacks during login.

2) encrypt_val/decrypt_val (Confidentiality): Uses AES-GCM (Galois/Counter Mode) to encrypt sensitive data.
This mode provides both encryption and an Authentication Tag to instantly detect if the ciphertext was tampered with.

3) compute_hmac (Integrity): Uses HMAC-SHA256 to generate cryptographic signature for database rows,ensuring data hasn't been altered by unauthorized users.

4) get_row_bytes (Formatting): Performs Canonicalization by joining values with |, ensuring data is formatted identically every time before hashing.
'''



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