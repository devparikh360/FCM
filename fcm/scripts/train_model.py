from tqdm import tqdm
import pandas as pd
import json
import os
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# --- Paths ---
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # root folder
SCHEMA_FILE = os.path.join(ROOT_DIR, "schema.json")
MODEL_FILE_JSON = os.path.join(ROOT_DIR, "xgboost_model.json")
FEATURES_FILE_JSON = os.path.join(ROOT_DIR, "feature_columns.json")  # new file

# --- Load schema.json ---
with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
    schema = json.load(f)

# --- Flatten schema into rows ---
rows = []
for bucket in ["urls", "apps", "content"]:
    for k, v in schema.get(bucket, {}).items():
        row = v.copy()
        row["id"] = k
        row["type"] = bucket
        row["label"] = 1 if v.get("threat_label", "") != "legit" else 0
        rows.append(row)

df = pd.DataFrame(rows)

# --- Features & Labels ---
X = pd.json_normalize(df["features"])  # flatten nested dict into columns
y = df["label"]

# Check class balance
print("\nClass distribution:")
print(y.value_counts())
print("\nPercentage distribution:")
print(y.value_counts(normalize=True) * 100)

# --- Convert object/list columns to numeric ---
for col in X.columns:
    if X[col].dtype == 'object':
        # Convert lists to strings
        X[col] = X[col].apply(lambda x: str(x) if isinstance(x, list) else x)
        # Convert strings to category codes
        X[col] = X[col].astype('category').cat.codes

# --- Train/test split ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# --- Train Model with tqdm ---
model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    random_state=42,
    enable_categorical=True  # ensures categorical columns are supported
    n_jobs=-1 
    tree_method="gpu_hist"
)

print("\nTraining model...")
for _ in tqdm(range(1)):
    model.fit(X_train, y_train)

print("✅ Training complete!")

# --- Evaluate ---
y_pred = model.predict(X_test)
print("\nModel Performance:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# --- Save model as JSON for engine.py ---
model.save_model(MODEL_FILE_JSON)
print(f"✅ ML model saved as {MODEL_FILE_JSON}")

# --- Save feature columns for engine.py ---
FEATURE_COLUMNS = list(X_train.columns)
with open(FEATURES_FILE_JSON, "w", encoding="utf-8") as f:
    json.dump(FEATURE_COLUMNS, f, indent=2)
print(f"✅ Feature columns saved as {FEATURES_FILE_JSON}")

with open("feature_columns.json", "w") as f:
    json.dump(list(X.columns), f)
