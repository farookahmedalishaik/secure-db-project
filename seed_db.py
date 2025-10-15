# seed_db.py
import os
import hashlib
import secrets
from faker import Faker
import mysql.connector
from dotenv import load_dotenv

load_dotenv()  # reads .env

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "secure_db")
DB_USER = os.getenv("DB_USER", "secure_user")
DB_PASS = os.getenv("DB_PASS", "")

NUM_ROWS = 120  # >= 100 as required

fake = Faker()

# --- Custom Health History Generator (NEW CODE) ---
# Define lists of realistic medical terms
CONDITIONS = [
    "Hypertension", "Type 2 Diabetes", "Asthma", "Seasonal allergies",
    "Minor back pain", "Anxiety", "High cholesterol", "Migraines"
]
STATUSES = [
    "well-managed", "stable", "under observation", "showing improvement",
    "monitored", "controlled with medication"
]
NOTES = [
    "Patient reports consistent energy levels.",
    "Monitors blood pressure at home.",
    "Follows a prescribed dietary plan.",
    "Uses an inhaler as needed.",
    "No new symptoms reported during last visit."
]

def generate_health_history():
    """
    Creates a more realistic-looking health history note.
    """
    # Pick one random item from each list
    condition = secrets.choice(CONDITIONS)
    status = secrets.choice(STATUSES)
    note = secrets.choice(NOTES)

    # Assemble the items into a short paragraph
    history_paragraph = f"Patient diagnosed with {condition}. The condition is currently {status}. {note}"
    return history_paragraph
# --- End of Custom Generator ---


def canonical_row_bytes(first_name, last_name, gender, age, weight, height, health_history):
    """
    Create a canonical byte representation (deterministic) for hashing.
    Use '|' as separator and encode to utf-8.
    """
    parts = [
        str(first_name).strip(),
        str(last_name).strip(),
        str(int(gender)),  # ensure 0/1
        str(int(age)),
        f"{float(weight):.3f}",
        f"{float(height):.3f}",
        str(health_history).strip()
    ]
    joined = "|".join(parts)
    return joined.encode("utf-8")

def compute_merkle_leaf(first_name, last_name, gender, age, weight, height, health_history):
    b = canonical_row_bytes(first_name, last_name, gender, age, weight, height, health_history)
    h = hashlib.sha256(b).digest()  # 32 bytes
    return h

def main():
    cnx = mysql.connector.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, database=DB_NAME
    )
    cursor = cnx.cursor(prepared=True)

    insert_sql = """
    INSERT INTO patients
    (first_name, last_name, gender, age, weight, height, health_history, row_token, merkle_leaf)
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """

    for i in range(NUM_ROWS):
        first = fake.first_name()
        last = fake.last_name()
        # gender boolean: 0 or 1 (random)
        gender = secrets.choice([0, 1])
        age = secrets.choice(range(0, 100))
        weight = round(50 + secrets.randbelow(90) * 0.5 + fake.random.random(), 2)  # 50 - 95 approx
        height = round(140 + secrets.randbelow(60) * 0.5 + fake.random.random(), 2) # 140 - 170 approx
        
        # health history: generate a custom, realistic note (UPDATED LINE)
        health_history = generate_health_history()

        row_token = secrets.token_bytes(16)  # 16-byte random token
        merkle_leaf = compute_merkle_leaf(first, last, gender, age, weight, height, health_history)

        params = (first, last, gender, age, weight, height, health_history, row_token, merkle_leaf)
        cursor.execute(insert_sql, params)

    cnx.commit()
    cursor.close()
    cnx.close()
    print(f"Inserted {NUM_ROWS} rows into patients table in database '{DB_NAME}'.")

if __name__ == "__main__":
    main()
