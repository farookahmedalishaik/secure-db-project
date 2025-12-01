import os
from config import get_db_conn, load_keys
from crypto_utils import encrypt_val, decrypt_val, compute_hmac, get_row_bytes
from integrity import build_merkle_tree, sha256

# File to store the trusted Merkle Root on the client side
CLIENT_ROOT_FILE = "client_root.bin"

def insert_patient(session, first, last, gender, age, weight, height, history):
    """
    Inserts a new patient. Only Group H allowed.
    Encrypts sensitive fields and computes integrity data.
    """
    if session['user_group'] != 'H':
        raise PermissionError("Access Denied: Group H only.")

    aes_k, hmac_k = load_keys()
    
    # 1. Encrypt Sensitive Data (Age & Gender)
    g_enc, g_n, g_t = encrypt_val(aes_k, int(gender))
    a_enc, a_n, a_t = encrypt_val(aes_k, int(age))
    
    # 2. Integrity: Compute HMAC of the row data
    r_bytes = get_row_bytes(first, last, weight, height, history)
    r_mac = compute_hmac(hmac_k, r_bytes)
    
    # 3. Integrity: Compute Merkle Leaf (Hash of the HMAC)
    leaf = sha256(r_mac)

    conn = get_db_conn()
    cur = conn.cursor()
    
    sql = """INSERT INTO patients 
             (first_name, last_name, gender_enc, gender_nonce, gender_tag, 
              age_enc, age_nonce, age_tag, weight, height, health_history, 
              row_hmac, merkle_leaf) 
             VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
             
    cur.execute(sql, (first, last, g_enc, g_n, g_t, a_enc, a_n, a_t, 
                      weight, height, history, r_mac, leaf))
    conn.commit()
    conn.close()
    print("✅ Record inserted successfully.")

def update_client_trust():
    """
    Downloads all merkle leaves from the server, computes the root, 
    and saves it to a local file. This establishes 'Trust'.
    """
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT merkle_leaf FROM patients ORDER BY id")
    leaves = [r[0] for r in cur.fetchall()]
    conn.close()
    
    # Rebuild tree and save root
    root, _ = build_merkle_tree(leaves)
    with open(CLIENT_ROOT_FILE, "wb") as f:
        f.write(root)
    print(f"🔄 Trusted Root Updated: {root.hex()[:8]}...")

def get_trusted_root():
    """Reads the locally saved trusted root."""
    if not os.path.exists(CLIENT_ROOT_FILE):
        return None
    with open(CLIENT_ROOT_FILE, "rb") as f:
        return f.read()

def query_patients(session):
    """
    Fetches data, verifies Integrity/Completeness, and Redacts based on group.
    RETURNS TWO VALUES: (results_list, status_message)
    """
    aes_k, hmac_k = load_keys()
    conn = get_db_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM patients ORDER BY id")
    rows = cur.fetchall()
    conn.close()

    # --- 1. COMPLETENESS CHECK (Merkle Tree) ---
    leaves = [r['merkle_leaf'] for r in rows]
    server_root, _ = build_merkle_tree(leaves)
    client_root = get_trusted_root()
    
    root_status = "✅ OK"
    if client_root is None:
        root_status = "⚠️ No Local Trust Found (Please run Option 4 or 6 to Init)"
    elif server_root != client_root:
        root_status = "❌ FAIL (Data Deleted or Tampered!)"

    results = []
    for r in rows:
        # --- 2. INTEGRITY CHECK (HMAC) ---
        # Re-compute hash of the data we received
        raw = get_row_bytes(r['first_name'], r['last_name'], r['weight'], r['height'], r['health_history'])
        calc_mac = compute_hmac(hmac_k, raw)
        
        # Compare with the HMAC stored in the database
        hmac_ok = (calc_mac == r['row_hmac'])

        # --- 3. CONFIDENTIALITY (Decryption) ---
        age = decrypt_val(aes_k, r['age_enc'], r['age_nonce'], r['age_tag'], int)
        gender = decrypt_val(aes_k, r['gender_enc'], r['gender_nonce'], r['gender_tag'], int)
        gender_str = "Male" if gender == 1 else "Female"

        # --- 4. ACCESS CONTROL (Redaction) ---
        f, l = r['first_name'], r['last_name']
        
        # If user is Group R (Reader), hide the names
        if session['user_group'] == 'R':
            f, l = "[REDACTED]", "[REDACTED]"
            
        results.append({
            "id": r['id'], 
            "first": f, 
            "last": l, 
            "age": age, 
            "gender": gender_str, 
            "weight": r['weight'],
            "integrity": "Pass" if hmac_ok else "FAIL"
        })
    
    # RETURN BOTH THE DATA AND THE STATUS
    return results, root_status