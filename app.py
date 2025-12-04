# app.py

'''
app.py serves as Central Controller and Command Line Interface (CLI). 
It orchestrates the entire application by importing and executing logic from all the other modules based on user input.
'''

import sys
import base64
from getpass import getpass
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv

# Import Logic
from db_setup import run_schema_native
from auth import create_user, login
from populate import seed_data
from access_control import insert_patient, query_patients, update_client_trust

def gen_keys():
    aes = base64.b64encode(get_random_bytes(32)).decode()
    hmac = base64.b64encode(get_random_bytes(32)).decode()
    print("\n Generated new keys:")
    print(f"\nAES_KEY_B64={aes}\nHMAC_KEY_B64={hmac}")
    print("\n PASTE THESE INTO .env FILE")

def main():
    while True:
        print("\n=== SECURE DB PROJECT MENU ===")
        print("1. Setup Database (Schema)")
        print("2. Generate Crypto Keys")
        print("3. Create Default Users (doctor_h / researcher_r)")
        print("4. Seed/Populate 100 Data Items to DB")
        print("5. Login & Query (Read Data)")
        print("6. Manual Insert (Group H Only)")
        print("7. Create New User")
        print("0. Exit")
        
        choice = input("Choice: ")
        
        if choice == "1":
            run_schema_native()

        elif choice == "2":
            gen_keys()

        elif choice == "3":
            create_user("doctor", "pwd_d", "H")
            create_user("researcher", "pwd_r", "R")
            print("Default users check complete.")

        elif choice == "4":
            try:
                seed_data(100)
            except RuntimeError as e:
                print(f"ERROR: {e}")

        elif choice == "5":
            u = input("Username: ")
            p = getpass("Password: ")
            sess = login(u, p)
            if sess:
                print(f"Logged in as Group: {sess['user_group']}")
                
                #SUB-MENU FOR QUERY
                print("\n   [1] View Top N Rows")
                print("   [2] Search by Specific ID")
                q_type = input("   Select Query Type: ").strip()
                
                # Fetch ALL data first (Required for Completeness/Merkle Check)
                
                try:
                    results, status = query_patients(sess)
                except RuntimeError as e:
                    print(f"ERROR: {e}")
                    continue

                print(f"\nCompleteness Check: {status}")
                print(f"{'ID':<5} {'First':<15} {'Last':<15} {'Age':<5} {'Gender':<10} {'Integrity'}")
                print("-" * 65)

                if q_type == "2":
                    # SEARCH BY ID LOGIC
                    try:
                        target_id = int(input("   Enter Patient ID to find: "))
                        found = False
                        for r in results:
                            if r['id'] == target_id:
                                print(f"{r['id']:<5} {r['first']:<15} {r['last']:<15} {r['age']:<5} {r['gender']:<10} {r['integrity']}")
                                found = True
                                break
                        if not found:
                            print(f"Patient ID {target_id} not found.")
                    except ValueError:
                        print("Invalid ID format.")
                
                else:
                    #DEFAULT TOP N ROWS LOGIC
                    limit_input = input("   How many rows to display? [Default 15]: ").strip()
                    limit = int(limit_input) if limit_input.isdigit() else 15
                    
                    for r in results[:limit]: 
                        print(f"{r['id']:<5} {r['first']:<15} {r['last']:<15} {r['age']:<5} {r['gender']:<10} {r['integrity']}")
                    
                    if len(results) > limit:
                        print(f"... ({len(results) - limit} more rows hidden) ...")

            else:
                print("Login Failed")

        elif choice == "6":
            u = input("Username (Group H): ")
            p = getpass("Password: ")
            sess = login(u, p)
            
            if sess and sess['user_group'] == 'H':
                print("\n--- Enter Patient Details ---")
                try:
                    f_name = input("First Name: ")
                    l_name = input("Last Name: ")
                    gender = int(input("Gender (0=Female, 1=Male): "))
                    age = int(input("Age (Years): "))
                    weight = float(input("Weight (lbs): ")) 
                    height = float(input("Height (cm): "))
                    hist = input("Health History (text): ")
                    
                    insert_patient(sess, f_name, l_name, gender, age, weight, height, hist)
                    update_client_trust()
                except ValueError:
                    print("Error: Please enter valid numbers for Age/Weight/Height.")
                except Exception as e:
                    print(f"Error: {e}")
            else:
                print("Access Denied: Only Group H can insert data.")

        elif choice == "7":
            print("\n--- Create New User ---")
            new_u = input("New Username: ").strip()
            new_p = getpass("New Password: ")
            new_g = input("Group (H for Full Access, R for Restricted): ").strip().upper()
            
            if new_g not in ['H', 'R']:
                print("Error: Group must be 'H' or 'R'.")
            else:
                create_user(new_u, new_p, new_g)
                print(f"User '{new_u}' added to Group '{new_g}'.")

        elif choice == "0":
            print("Exiting.")
            break

if __name__ == "__main__":
    main()