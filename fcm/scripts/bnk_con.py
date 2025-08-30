import os
import requests
from bs4 import BeautifulSoup
import firebase_admin
from firebase_admin import credentials, db
from datetime import datetime

SERVICE_KEY_PATH = os.path.join(os.path.dirname(__file__), 'fcmfbskp.json')
cred = credentials.Certificate(SERVICE_KEY_PATH)
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://fcm-app-40684-default-rtdb.firebaseio.com/'
})

def upload_to_firebase(content_list, category):
    if not content_list:
        print("No content to upload for", category)
        return
    ref = db.reference(f"digital_content/{category}")
    for content in content_list:
        ref.push(content)
    print(f"✅ {category} digital content uploaded successfully!")

# Helper: scrape links from a webpage
def scrape_links(url, extensions):
    urls = []
    try:
        r = requests.get(url, timeout=15)
        soup = BeautifulSoup(r.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link['href']
            if any(href.lower().endswith(ext) for ext in extensions):
                urls.append(href if href.startswith('http') else url + href)
    except Exception as e:
        print(f"Error scraping {url}: {e}")
    return urls

# Sources
sources = [
    "https://github.com/topics/phishing?l=pdf",
    "https://pastebin.com/search?q=banking+phishing",
    "https://www.phishing.org/resources"  # Example, replace with real pages
]

banking_contents = []
for src in sources:
    links = scrape_links(src, ['.pdf', '.txt', '.docx', '.png', '.jpg'])
    for link in links:
        banking_contents.append({
            "title": link.split('/')[-1],
            "url": link,
            "category": "banking",
            "type": link.split('.')[-1],
            "source": src,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

upload_to_firebase(banking_contents, "banking")
