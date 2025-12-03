# auth.py

'''
auth.py acts as the Authentication Manager, responsible for securely registering and verifying user identities.

1) create_user fn is called, it first performs Input Validation to ensure the user belongs to a valid group ('H' or 'R'), 
then protects credentials by Salted Hashing—generating (unique random "salt") & combined with password (via hash_password) so plaintext passwords never stored in database. 

2) When a user attempts to access the system via login, the script retrieves their stored credentials and verifies their identity
by using verify_password to re-hash the input password with the stored salt, confirming access only if the result matches the database record perfectly.
'''



from config import get_db_conn
from crypto_utils import hash_password, verify_password
import mysql.connector

def create_user(username, password, group):
    """Register a new user (Group H or R)"""
    if group not in ('H', 'R'):
        print("Error: Invalid group. Use 'H' or 'R'.")
        return

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
    except mysql.connector.IntegrityError as e:
        # Typically thrown for UNIQUE constraint violations
        print(f"User creation failed: username '{username}' may already exist.")
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