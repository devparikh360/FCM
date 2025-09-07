import os
import json
import firebase_admin
from firebase_admin import credentials, firestore

# Project root (one level up from scripts/)
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_FILE = os.path.join(ROOT_DIR, "schema.json")

# Firebase key is inside scripts/
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fcmfbskp.json")

# Init Firebase
cred = credentials.Certificate(KEY_FILE)
firebase_admin.initialize_app(cred)
db = firestore.client()

# Load schema.json
if not os.path.exists(SCHEMA_FILE):
    raise FileNotFoundError(f" schema.json not found at {SCHEMA_FILE}")

with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
    schema = json.load(f)

# Upload to Firestore
doc_ref = db.collection("threat_data").document("schema")

# Store schema as a single JSON string
doc_ref.set({
    "schema_json": json.dumps(schema)   # everything in one field
})

print("schema.json uploaded successfully to Firestore as a single field")
