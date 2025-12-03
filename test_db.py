# test_db.py

# this is just to make sure the connection is esatablished or not using config.py's get_db_conn
from config import get_db_conn

conn = get_db_conn()
print("[OK] Connected to MySQL!")
conn.close()
