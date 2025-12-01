# test_db.py

from config import get_db_conn

conn = get_db_conn()
print("[OK] Connected to MySQL!")
conn.close()
