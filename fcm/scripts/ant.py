# scripts/add_and_train.py
import os
import json
import subprocess
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SCHEMA_FILE = os.path.join(ROOT_DIR, "schema.json")

# --- New data to add ---
new_urls = {
    "urls": {
        "http://test-malicious.com": {
            "threat_label": "malicious",
            "description": "Test malicious URL"
        },
        "http://safe-example.com": {
            "threat_label": "legit",
            "description": "Test safe URL"
        }
    },
    "apps": {},
    "content": {}
}

# --- Load existing schema ---
if os.path.exists(SCHEMA_FILE):
    with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
        schema = json.load(f)
else:
    schema = {"urls": {}, "apps": {}, "content": {}}

# --- Merge new data ---
for bucket in ["urls", "apps", "content"]:
    schema.setdefault(bucket, {})
    schema[bucket].update(new_urls.get(bucket, {}))

# --- Save updated schema ---
with open(SCHEMA_FILE, "w", encoding="utf-8") as f:
    json.dump(schema, f, indent=2)
print("✅ New test URLs added to schema.json")

# --- Trigger training ---
print("⏳ Running train_model.py...")
#subprocess.run(["python", os.path.join(ROOT_DIR, "scripts", "train_model.py")])
#import sys
cmd = ["python", "scripts/train_model.py"] + sys.argv[1:]  # pass any extra args
subprocess.run(cmd, check=True)

