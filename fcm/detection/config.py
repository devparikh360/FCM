import os

# Resolve service key relative to this file by default, but allow env override
SERVICE_KEY_PATH = os.environ.get(
    "FCM_SERVICE_ACCOUNT",
    os.path.join(os.path.dirname(__file__), "..", "scripts", "fcmfbskp.json")
)

# Your RTDB URL
RTDB_URL = "https://fcm-app-40684-default-rtdb.firebaseio.com/"

# Firebase paths we read from
PATHS_IN = {
    "banking_urls": "banking_urls/urls",     # you fixed the nesting to .../urls
    "social_urls": "social_media_urls/urls",
    "banking_apps": "apps/banking",
    "social_apps": "apps/social_media",
    "banking_content": "digital_content/banking",
    "social_content": "digital_content/social_media",
}

# Where we write detections
PATHS_OUT = {
    "url": "detections/urls",
    "app": "detections/apps",
    "content": "detections/content",
}
