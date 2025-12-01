import os
import mysql.connector
from getpass import getpass
from config import DB_HOST, DB_PORT, DB_USER, DB_PASS

def run_schema_native():
    print(f"Applying schema to {DB_HOST}...")
    try:
        # Connect to server directly (no DB selected yet)
        cnx = mysql.connector.connect(
            host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS
        )
        cursor = cnx.cursor()
        
        with open("schema.sql", "r") as f:
            statements = f.read().split(';')
            
        for stmt in statements:
            if stmt.strip():
                cursor.execute(stmt)
                
        print("✅ Schema applied successfully.")
        cnx.commit()
        cursor.close()
        cnx.close()
    except Exception as e:
        print(f"❌ Database Error: {e}")