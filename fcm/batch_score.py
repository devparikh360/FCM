import os
import json
import firebase_admin
from firebase_admin import credentials, firestore
from detection.engine import score_url, score_app, score_content
from tqdm import tqdm

# --- Auto-detect root directory ---
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Firebase key ---
KEY_FILE = os.path.join(ROOT_DIR, "scripts", "fcmfbskp.json")
cred = credentials.Certificate(KEY_FILE)
firebase_admin.initialize_app(cred)
db = firestore.client()

# --- Load schema from Firestore ---
SCHEMA_DOC = db.collection("threat_data").document("schema")
raw_schema = SCHEMA_DOC.get().to_dict()

if not raw_schema or "schema_json" not in raw_schema:
    print("❌ No schema found in Firestore!")
    exit()

# Convert Firestore string → dict
try:
    schema = json.loads(raw_schema["schema_json"])
except Exception as e:
    print("❌ Failed to parse schema_json:", e)
    exit()

print(f"✅ Loaded schema with keys: {list(schema.keys())}")

# --- Prepare collection for scored results ---
SCORED_COLLECTION = db.collection("threat_data").document("scored")

# --- Flatten schema into items ---
items = []
for bucket in ["urls", "apps", "content"]:
    for k, v in schema.get(bucket, {}).items():
        v["id"] = k
        v["type"] = bucket
        items.append(v)

# --- Score items with progress bar ---
scored_data = {"urls": {}, "apps": {}, "content": {}}

for item in tqdm(items, desc="Scoring items"):
    item_id = item["id"]
    item_type = item["type"]
    sector = item.get("sector", "general")

    if item_type == "urls":
        url = item.get("url") or item.get("link", "")
        scored = score_url(url, sector=sector)
    elif item_type == "apps":
        platform = item.get("platform", "android")
        link = item.get("link") or item.get("url", "")
        scored = score_app(link, platform=platform, sector=sector)
    elif item_type == "content":
        text = item.get("text") or item.get("content") or ""
        scored = score_content(text, sector=sector)
    else:
        print(f"⚠️ Unknown type '{item_type}' for item {item_id}")
        continue

scored_data[item_type][item_id] = {
    "sector": sector,
    "score": scored,
}


# --- Upload scored results ---
SCORED_COLLECTION.set(scored_data)
print("✅ Batch scoring complete and uploaded to Firestore")
