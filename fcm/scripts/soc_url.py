import os
import requests
import firebase_admin
from firebase_admin import credentials, db
from datetime import datetime

# Dynamic path to the Firebase service account key
SERVICE_KEY_PATH = os.path.join(os.path.dirname(__file__), 'fcmfbskp.json')

# Firebase initialization
cred = credentials.Certificate(SERVICE_KEY_PATH)
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://fcm-app-40684-default-rtdb.firebaseio.com/'
})

def upload_to_firebase(urls):
    if not urls:
        print("No URLs to upload.")
        return

    ref = db.reference("social_media_urls")
    for url in urls:
        metadata = {
            "url": url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": "phishtank",
            "category": "social_media"
        }
        ref.push(metadata)
    print("✅ Upload successful!")

# Fetch phishing URLs
try:
    response = requests.get("https://phish.sinking.yachts/v2/all", timeout=15)
    response.raise_for_status()
    data = response.json()
    print(f"Fetched {len(data)} entries.")
except Exception as e:
    print("Error fetching data:", e)
    data = []

# Social media keywords
keywords = ["facebook", "instagram", "whatsapp", "twitter", "linkedin", "snapchat", "tiktok", "telegram", "discord"]

# Filter social media URLs
social_urls = [entry for entry in data if any(k in entry.lower() for k in keywords)]

print(f"Social media-related URLs found: {len(social_urls)}")

# Upload
upload_to_firebase(social_urls)
