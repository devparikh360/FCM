import os
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, db
from google_play_scraper import search as gp_search

# Firebase setup
SERVICE_KEY_PATH = os.path.join(os.path.dirname(__file__), 'fcmfbskp.json')
cred = credentials.Certificate(SERVICE_KEY_PATH)
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://fcm-app-40684-default-rtdb.firebaseio.com/'
})

# Firebase upload function
def upload_to_firebase(apps, category):
    if not apps:
        print("No apps found for", category)
        return
    ref = db.reference(f"apps/{category}")
    for app in apps:
        metadata = {
            "name": app['title'],
            "url": f"https://play.google.com/store/apps/details?id={app['appId']}",
            "category": category,
            "source": "playstore",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        ref.push(metadata)
    print(f"✅ {category} apps uploaded successfully!")

# Keywords for banking apps
bank_keywords = ["bank", "credit", "loan", "payment", "wallet"]

# Fetch banking apps
banking_apps = []
for kw in bank_keywords:
    results = gp_search(kw, lang='en', country='us', n_hits=20)
    banking_apps.extend(results)

# Remove duplicates by appId
seen = set()
unique_banking = []
for app in banking_apps:
    if app['appId'] not in seen:
        unique_banking.append(app)
        seen.add(app['appId'])

# Upload to Firebase
upload_to_firebase(unique_banking, "banking")
