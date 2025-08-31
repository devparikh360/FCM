"""
patched_api.py

A drop-in enhanced version of your FCM/fcm/api.py that:
 - Initializes Firebase Admin (RTDB + Firestore) from GOOGLE_APPLICATION_CREDENTIALS or local service key.
 - Runs your local detection engine (score_url/score_app/score_content).
 - Saves each detection to Realtime DB (/detections) and Firestore ('detections' collection).
 - Returns JSON to the frontend (same shape as original).
USAGE:
  - Place this file inside the FCM/fcm/ folder (next to api.py).
  - Set environment variable GOOGLE_APPLICATION_CREDENTIALS to your service account JSON path
    (OR keep the scripts/fcmfbskp.json but DO NOT commit it to git).
  - From FCM/fcm directory run:
        export GOOGLE_APPLICATION_CREDENTIALS=./scripts/fcmfbskp.json
        pip install flask flask-cors firebase-admin requests
        python patched_api.py
"""

import os
import sys
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

# Ensure current package path is visible so imports like `from detection.engine import ...` work
BASE_DIR = os.path.dirname(__file__)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Import detection functions from your engine (same as original)
try:
    from detection.engine import score_url, score_content, score_app
except Exception as e:
    # Helpful error message if import fails
    raise ImportError("Couldn't import detection.engine. Run this script from inside the FCM/fcm directory "
                      "(so the 'detection' package is on PYTHONPATH). Original error: " + str(e))

# Firebase Admin initialization (Realtime DB + Firestore)
import firebase_admin
from firebase_admin import credentials, firestore, db as rtdb

FIREBASE_SA = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", os.path.join(BASE_DIR, "scripts", "fcmfbskp.json"))
FIREBASE_RTDB_URL = os.environ.get("FIREBASE_DB_URL", "https://fcm-app-40684-default-rtdb.firebaseio.com/")

if not firebase_admin._apps:
    if not os.path.exists(FIREBASE_SA):
        raise FileNotFoundError(f"Service account JSON not found at {FIREBASE_SA}. Set GOOGLE_APPLICATION_CREDENTIALS.")
    cred = credentials.Certificate(FIREBASE_SA)
    firebase_admin.initialize_app(cred, {
        "databaseURL": FIREBASE_RTDB_URL
    })

firestore_client = firestore.client()
rtdb_root = rtdb.reference("/")  # root ref

app = Flask(__name__)
CORS(app)


def _save_detection(url, category, result):
    """
    Save detection result to both RTDB and Firestore.
    category: 'url' / 'app' / 'content' - useful to separate later
    """
    payload = {
        "category": category,
        "url": url,
        "result": result,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    # RTDB push
    try:
        detections_ref = rtdb_root.child("detections")
        detections_ref.push(payload)
    except Exception as e:
        app.logger.warning("Failed to write to RTDB: %s", e)

    # Firestore write
    try:
        firestore_client.collection("detections").add(payload)
    except Exception as e:
        app.logger.warning("Failed to write to Firestore: %s", e)


# --- Detect URL ---
@app.route("/detect/url", methods=["POST"])
def detect_url():
    data = request.get_json(force=True)
    url = data.get("url")
    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    # Run detection engine
    result = score_url(url)

    # Save to Firebase (RTDB + Firestore) for history/audit
    try:
        _save_detection(url, "url", result)
    except Exception as e:
        app.logger.error("Error saving detection: %s", e)

    # Return normalized response that UI expects
    response = {
        "url": url,
        "result": result,
        "score": result.get("score"),
        "status": result.get("status")
    }
    return jsonify(response), 200


# --- Detect App Metadata ---
@app.route("/detect/app", methods=["POST"])
def detect_app():
    data = request.get_json(force=True)
    app_info = data.get("app_info")
    if not app_info:
        return jsonify({"error": "Missing 'app_info'"}), 400

    result = score_app(app_info)
    try:
        _save_detection(app_info.get("url") or app_info.get("package") or "<unknown>", "app", result)
    except Exception as e:
        app.logger.error("Error saving detection: %s", e)

    return jsonify({"app_info": app_info, "result": result}), 200


# --- Detect Content (direct download links, docs, etc) ---
@app.route("/detect/content", methods=["POST"])
def detect_content():
    data = request.get_json(force=True)
    url = data.get("url")
    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    result = score_content(url)
    try:
        _save_detection(url, "content", result)
    except Exception as e:
        app.logger.error("Error saving detection: %s", e)

    return jsonify({"url": url, "result": result}), 200


if __name__ == "__main__":
    # Helpful startup log
    print("Starting patched API on http://0.0.0.0:5000")
    print("Using service account:", FIREBASE_SA)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
