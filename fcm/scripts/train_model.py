from tqdm import tqdm
import pandas as pd
import json
import os
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from collections import Counter
import joblib
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--force", action="store_true", help="Force full retrain")
args = parser.parse_args()

# --- Paths ---
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_FILE = os.path.join(ROOT_DIR, "schema.json")
MODEL_FILE_JSON = os.path.join(ROOT_DIR, "xgboost_model.json")
FEATURES_FILE_JSON = os.path.join(ROOT_DIR, "feature_columns.json")
TRAINED_URLS_FILE = os.path.join(ROOT_DIR, "trained_urls.json")
OLD_DATA_FILE = os.path.join(ROOT_DIR, "old_training_data.pkl")
MAX_OLD_SAMPLES = 5000

# --- External data sources (path, label, type) ---
DATA_SOURCES = [
    ("data/leg.txt", 0, "urls"),                  # legit URLs
    ("data/feed.txt", 1, "urls"),                 # fake/malicious URLs
    ("data/phishing-domains-ACTIVE.adblock", 1, "urls"),
    ("data/urlhaus_full.json", 1, "content")      # JSON with malicious URLs
]

# --- Load trained URLs ---
if os.path.exists(TRAINED_URLS_FILE):
    with open(TRAINED_URLS_FILE, "r") as f:
        trained_urls = set(json.load(f))
else:
    trained_urls = set()

# --- Load schema.json ---
with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
    schema = json.load(f)

# --- Flatten schema into rows ---
rows = []
for bucket in ["urls", "apps", "content"]:
    for k, v in schema.get(bucket, {}).items():
        if k in trained_urls:
            continue
        row = v.copy()
        row["id"] = k
        row["type"] = bucket
        row["label"] = 1 if v.get("threat_label", "") != "legit" else 0
        rows.append(row)

# --- Feature extraction functions ---
from detection.features_url import extract_url_features
from detection.features_app import extract_app_features
from detection.features_content import extract_content_features

# --- Add all external data sources ---
for path, label, typ in DATA_SOURCES:
    full_path = os.path.join(ROOT_DIR, path)
    if not os.path.exists(full_path):
        print(f"⚠️ {path} not found, skipping.")
        continue

    if path.endswith(".txt") or path.endswith(".adblock"):
        with open(full_path, "r", encoding="utf-8") as f:
            items = [line.strip() for line in f if line.strip()]
    else:  # JSON file
        with open(full_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Flatten JSON structure: get 'url' from each entry
            items = []
            for entries in data.values():
                for entry in entries:
                    url = entry.get("url")
                    if url:
                        items.append(url)

    for item in items:
        if item in trained_urls and not args.force:
            continue
        if typ == "urls":
            features = extract_url_features(item)
        elif typ == "content":
            features = extract_content_features(item)
        else:
            continue
        if not features:
            continue
        rows.append({"id": item, "type": typ, "label": label, "features": features})

print(f"✅ Total new rows to process: {len(rows)}")


if not rows and not args.force:
    print("✅ No new data to train. Exiting...")
    exit()

# --- Prepare features & labels ---
X_list, y_list, ids_list = [], [], []
for row in tqdm(rows, desc="Extracting features"):
    if not row.get("features"):
        if row["type"] == "urls":
            row["features"] = extract_url_features(row["id"])
        elif row["type"] == "apps":
            row["features"] = extract_app_features(row["id"], platform=row.get("platform", "android"))
        elif row["type"] == "content":
            row["features"] = extract_content_features(row["id"])
    features = row.get("features", {})
    if not features:
        continue
    X_list.append(features)
    y_list.append(row["label"])
    ids_list.append(row["id"])

if not X_list:
    print("⚠️ No valid feature data found. Exiting...")
    exit()

# Convert to DataFrame and numeric
import numpy as np
X_new = pd.DataFrame(X_list).apply(pd.to_numeric, errors='coerce').fillna(0)
y_new = pd.Series(y_list)

# Replace infinite values and clip extreme values
X_new = X_new.replace([np.inf, -np.inf], 0)
X_new = X_new.clip(-1e10, 1e10)  # optional: caps huge values to avoid overflow

# --- Load old training data ---
X_old, y_old = None, None
if os.path.exists(OLD_DATA_FILE):
    try:
        X_old, y_old = joblib.load(OLD_DATA_FILE)
        X_old = X_old.reindex(columns=X_new.columns, fill_value=0)
        if len(X_old) > MAX_OLD_SAMPLES:
            X_old = X_old.sample(n=MAX_OLD_SAMPLES, random_state=42)
            y_old = y_old.loc[X_old.index]
    except Exception:
        X_old, y_old = None, None

# --- Merge old + new ---
if X_old is not None and y_old is not None:
    X_all = pd.concat([X_old, X_new], ignore_index=True)
    y_all = pd.concat([y_old, y_new], ignore_index=True)
else:
    X_all, y_all = X_new, y_new

# --- Ensure both classes exist ---
class_counts = Counter(y_all)
print("Class distribution:", class_counts)
if len(class_counts) < 2 or min(class_counts.values()) < 2:
    print("⚠️ Not enough samples for both classes. Skipping training.")
    exit()

# --- Train/test split ---
X_train, X_test, y_train, y_test = train_test_split(
    X_all, y_all, test_size=0.2, random_state=42, stratify=y_all
)

# --- Initialize XGBoost ---
model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    random_state=42,
    enable_categorical=True,
    n_jobs=-1,
    tree_method="gpu_hist",
    device="cuda",
    base_score=0.5
)

# --- Train model ---
print(f"Training model on {len(X_train)} samples...")
model.fit(X_train, y_train)
print("✅ Training complete!")

# --- Evaluate ---
y_pred = model.predict(X_test)
print("\nModel Performance:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# --- Save model & features ---
model.save_model(MODEL_FILE_JSON)
print(f"✅ ML model saved as {MODEL_FILE_JSON}")

FEATURE_COLUMNS = list(X_all.columns)
with open(FEATURES_FILE_JSON, "w", encoding="utf-8") as f:
    json.dump(FEATURE_COLUMNS, f, indent=2)
print(f"✅ Feature columns saved as {FEATURES_FILE_JSON}")

# --- Save current training data ---
joblib.dump((X_all, y_all), OLD_DATA_FILE)

# --- Update trained URLs ---
trained_urls.update(ids_list)
with open(TRAINED_URLS_FILE, "w") as f:
    json.dump(list(trained_urls), f)
print(f"✅ Updated trained URLs ({len(trained_urls)} total)")
