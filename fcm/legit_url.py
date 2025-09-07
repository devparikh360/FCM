import json
import os
import random

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SCHEMA_FILE = os.path.join(ROOT_DIR, "schema.json")

# Load your existing schema
with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
    schema = json.load(f)

# --- Function to add legit entries ---
def add_legit_entries(bucket, n=3):
    for i in range(n):
        key = f"legit_{bucket}_{i+1}"
        if bucket == "urls":
            schema[bucket][key] = {
                "features": {
                    "scheme": "https",
                    "host_is_ip": False,
                    "length": random.randint(15, 50),
                    "tld": "com",
                    "ssl_valid": True,
                    "contains_at": False,
                    "hyphens": 0,
                    "subdomain_depth": 1,
                    "digits_ratio": 0.0,
                    "is_punycode": False,
                    "homograph": False,
                    "domain_age_days": 400,
                    "word_hits": [],
                    "brand_similarity": {},
                    "redirect_count": 0
                },
                "threat_label": "legit",
                "sector": "general"
            }
        elif bucket == "apps":
            schema[bucket][key] = {
                "features": {
                    "direct_apk": False,
                    "direct_ipa": False,
                    "is_official_store": True,
                    "scam_hits": [],
                    "shortened": False,
                    "contains_id_param": False,
                    "length": random.randint(20, 60),
                    "https": True
                },
                "threat_label": "legit",
                "sector": "general"
            }
        elif bucket == "content":
            schema[bucket][key] = {
                "features": {
                    "is_dangerous": False,
                    "suspicious_patterns": False,
                    "digits_in_filename_ratio": 0.0,
                    "special_chars_in_filename": 0,
                    "has_bait_words": False,
                    "very_long_query": False,
                    "contains_double_ext": False,
                    "recognized_ext": True,
                    "is_known_doc": True,
                    "is_image": False,
                },
                "threat_label": "legit",
                "sector": "general"
            }

# Add 3 legit entries per bucket
for b in ["urls", "apps", "content"]:
    add_legit_entries(b, n=3)

# Save updated schema
with open(SCHEMA_FILE, "w", encoding="utf-8") as f:
    json.dump(schema, f, indent=2)

print("✅ Added legit entries to schema.json")
