from faker import Faker
import random
from access_control import insert_patient, update_client_trust
from auth import create_user

# Realistic medical data pools
HISTORY_HEALTHY = [
    "No significant medical history.",
    "Patient is in good health; regular checkups.",
    "No known allergies or chronic conditions."
]

HISTORY_MILD = [
    "Seasonal allergies, controlled with OTC meds.",
    "Mild asthma, occasional inhaler use.",
    "Vitamin D deficiency, on supplements.",
    "Occasional migraines, managed with diet.",
    "Minor joint pain in knees after exercise.",
    "Acid reflux (GERD), managed with diet."
]

HISTORY_SERIOUS = [
    "Type 2 Diabetes, insulin dependent.",
    "Hypertension (High Blood Pressure), daily medication.",
    "History of cardiac arrhythmia.",
    "Chronic Obstructive Pulmonary Disease (COPD).",
    "Rheumatoid Arthritis, requires physical therapy.",
    "Recovering from recent surgery (Appendectomy)."
]

def get_realistic_history():
    """Returns a history string based on probability weights."""
    # 15% Healthy, 55% Mild, 30% Serious
    category = random.choices(
        ['healthy', 'mild', 'serious'], 
        weights=[15, 55, 30], 
        k=1
    )[0]
    
    if category == 'healthy':
        return random.choice(HISTORY_HEALTHY)
    elif category == 'mild':
        return random.choice(HISTORY_MILD)
    else:
        return random.choice(HISTORY_SERIOUS)

def seed_data(count=100):
    print(f"🌱 Seeding {count} fake patients with realistic history...")
    fake = Faker()
    
    # --- CHANGE: Create 'doctor' instead of 'admin_h' ---
    # We create the doctor user here to ensure they exist 
    # so we can use their permissions to insert data.
    try: 
        create_user("doctor", "pwd_d", "H")
    except: 
        pass
        
    # Simulate the Doctor's session (Group H)
    session = {"user_group": "H"}
    
    for i in range(count):
        first = fake.first_name()
        last = fake.last_name()
        gender = random.choice([0, 1])
        age = random.randint(18, 90)
        weight = round(random.uniform(50.0, 120.0), 2)
        height = round(random.uniform(150.0, 200.0), 2)
        
        history = get_realistic_history()
        
        insert_patient(session, first, last, gender, age, weight, height, history)
        
        if (i+1) % 20 == 0:
            print(f"   ...inserted {i+1} records")
        
    # Update merkle root after seeding
    update_client_trust()
    print("✅ Seeding complete.")