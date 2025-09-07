import sys
import os
import json

# ---- Add root folder to sys.path BEFORE imports ----
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT_DIR)

from process_feeds import process_files
from detection.engine import score_url, score_app, score_content

# ---- Process all files in data/ folder ----
schema = process_files()

# ---- Save fully populated schema.json ----
OUTPUT_FILE = os.path.join(ROOT_DIR, "schema.json")
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(schema, f, indent=2)

print(f"schema.json created at {OUTPUT_FILE} with all URLs, apps, and content!")
