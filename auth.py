# auth.py

from config import get_db_conn
from crypto_utils import hash_password, verify_password

def create_user(username, password, group):
    """Register a new user (Group H or R)"""
    salt, p_hash = hash_password(password)
    conn = get_db_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_salt, password_hash, user_group) VALUES (%s, %s, %s, %s)",
            (username, salt, p_hash, group)
        )
        conn.commit()
        print(f"Created user {username} ({group})")
    except Exception as e:
        print(f"User creation failed: {e}")
    finally:
        conn.close()

def login(username, password):
    """Returns user dict if valid, else None"""
    conn = get_db_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    conn.close()
    
    if user and verify_password(user['password_salt'], user['password_hash'], password):
        return user
    return None