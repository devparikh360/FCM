import os
import requests
from bs4 import BeautifulSoup
import firebase_admin
from firebase_admin import credentials, db
from datetime import datetime

# Firebase setup
SERVICE_KEY_PATH = os.path.join(os.path.dirname(__file__), 'fcmfbskp.json')
cred = credentials.Certificate(SERVICE_KEY_PATH)
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://fcm-app-40684-default-rtdb.firebaseio.com/'
})

# Upload function
def upload_to_firebase(contents, category):
    if not contents:
        print(f"No content to upload for {category}")
        return
    ref = db.reference(f"digital_content/{category}")
    for content in contents:
        ref.push(content)
    print(f"✅ {category} digital content uploaded successfully!")

# Function to scrape links from a page
def scrape_links(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                links.append({
                    "url": href,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "source": url
                })
        return links
    except Exception as e:
        print(f"Error scraping {url}: {e}")
        return []

# Real social media sources (public)
sources = [
    "https://www.reddit.com/r/news/",
    "https://www.reddit.com/r/technology/",
    "https://medium.com/tag/social-media"
]

# Collect content
all_content = []
for src in sources:
    content = scrape_links(src)
    if content:
        all_content.extend(content)

# Upload to Firebase
upload_to_firebase(all_content, "social_media")
