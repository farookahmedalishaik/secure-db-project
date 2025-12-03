# db_setup.py

'''
db_setup.py is the Schema Initializer, responsible for building the database structure from scratch.

run_schema_native fn establishes a raw connection to the MySQL server using mysql.connector.
It reads the external schema.sql file, uses String Parsing (split(';')) to isolate individual SQL commands,
and executes them sequentially via a Database Cursor to create tables and define constraints, ensuring all changes are saved with a final Commit.
'''


import os
import mysql.connector
from getpass import getpass
from config import DB_HOST, DB_PORT, DB_USER, DB_PASS

def run_schema_native():
    print(f"Applying schema to {DB_HOST}...")
    try:
        # Connect to server directly
        cnx = mysql.connector.connect(
            host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS
        )
        cursor = cnx.cursor()
        
        with open("schema.sql", "r") as f:
            statements = f.read().split(';')
            
        for stmt in statements:
            if stmt.strip():
                cursor.execute(stmt)
                
        print("Schema applied successfully.")
        cnx.commit()
        cursor.close()
        cnx.close()
    except Exception as e:
        print(f"Database Error: {e}")