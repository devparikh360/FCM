import os
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, db
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SERVICE_KEY_PATH, RTDB_URL, PATHS_IN, PATHS_OUT

from detection.engine import score_url, score_app, score_content


def init_firebase():
    if not firebase_admin._apps:
        cred = credentials.Certificate(SERVICE_KEY_PATH)
        firebase_admin.initialize_app(cred, {'databaseURL': RTDB_URL})

def read_list(path):
    """
    Reads a list-like collection from RTDB.
    Handles both arrays and push-key maps; normalizes to list of items (dicts or strings).
    """
    ref = db.reference(path)
    snap = ref.get()
    out = []
    if not snap: 
        return out
    if isinstance(snap, list):
        out = [x for x in snap if x]
    elif isinstance(snap, dict):
        # values may be dicts with 'url' fields (your scripts push dicts)
        for _, v in snap.items():
            if v:
                out.append(v)
    return out

def write_detection(kind: str, payload: dict):
    out_path = PATHS_OUT[kind]
    ref = db.reference(out_path)
    ref.push(payload)

def process_urls(tag: str, path_in: str):
    items = read_list(path_in)
    if not items:
        print(f"[urls/{tag}] nothing to score")
        return
    print(f"[urls/{tag}] scoring {len(items)} items...")
    for it in items:
        u = it.get("url") if isinstance(it, dict) else str(it)
        if not u: 
            continue
        det = score_url(u)
        det["source_tag"] = tag
        write_detection("url", det)

def process_apps(tag: str, path_in: str, platform="android"):
    items = read_list(path_in)
    if not items:
        print(f"[apps/{tag}] nothing to score")
        return
    print(f"[apps/{tag}] scoring {len(items)} items...")
    for it in items:
        u = it.get("url") if isinstance(it, dict) else str(it)
        if not u: 
            continue
        det = score_app(u, platform=platform)
        det["source_tag"] = tag
        write_detection("app", det)

def process_content(tag: str, path_in: str):
    items = read_list(path_in)
    if not items:
        print(f"[content/{tag}] nothing to score")
        return
    print(f"[content/{tag}] scoring {len(items)} items...")
    for it in items:
        u = it.get("url") if isinstance(it, dict) else str(it)
        if not u: 
            continue
        det = score_content(u)
        det["source_tag"] = tag
        write_detection("content", det)

if __name__ == "__main__":
    init_firebase()

    # URLs
    process_urls("banking", PATHS_IN["banking_urls"])
    process_urls("social_media", PATHS_IN["social_urls"])

    # Apps
    process_apps("banking", PATHS_IN["banking_apps"], platform="android")
    process_apps("social_media", PATHS_IN["social_apps"], platform="android")

    # Content
    process_content("banking", PATHS_IN["banking_content"])
    process_content("social_media", PATHS_IN["social_content"])

    print("✅ Batch detection complete.")
