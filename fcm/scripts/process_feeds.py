import os
import json
import glob
import sys
from datetime import datetime
from time import time
#from engine import score_url, score_app, score_content
#from sectors import detect_sector
from detection.engine import score_url, score_app, score_content

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT_DIR)

# Load sector keywords from sectors.json
SECTOR_FILE = os.path.join(ROOT_DIR, "sectors.json")
with open(SECTOR_FILE, "r") as f:
    SECTOR_KEYWORDS = json.load(f)

def detect_sector(url: str) -> str:
    u = url.lower()
    for sector, keywords in SECTOR_KEYWORDS.items():
        if any(k in u for k in keywords):
            return sector
    return "general"

DATA_DIR = "data"
OUTPUT_FILE = "schema.json"

# -------- Helper: classify file type ----------
def classify_type(url: str) -> str:
    url_lower = url.lower()
    if url_lower.endswith(".apk"):
        return "app"
    elif any(url_lower.endswith(ext) for ext in [".exe", ".zip", ".rar", ".pdf", ".docx"]):
        return "content"
    else:
        return "url"

# -------- Process URLHAUS ----------
def process_urlhaus(file_path: str) -> dict:
    results = {"urls": {}, "apps": {}, "content": {}}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return results

    for idx, (_, entries) in enumerate(data.items(), 1):
        for j, entry in enumerate(entries, 1):
            url = entry.get("url")
            threat = entry.get("threat", "unknown")
            if not url:
                continue

            sector = detect_sector(url)
            typ = classify_type(url)

            try:
                if typ == "app":
                    result = score_app(url, platform="android", sector=sector)
                elif typ == "content":
                    result = score_content(url, sector=sector)
                else:
                    result = score_url(url, sector=sector)
            except Exception as e:
                print(f"Error scoring URL {url}: {e}")
                continue

            result.update({
                "sector": sector,
                "threat_label": threat,
                "source": "urlhaus",
                "file_name": os.path.basename(file_path),
                "file_type": "json",
                "collected_at": datetime.utcnow().isoformat() + "Z"
            })

            results[typ + "s"][url] = result

            if j % 100 == 0:
                print(f"  Processed {j} entries in {os.path.basename(file_path)}")

    return results

# -------- Process ADBLOCK ----------
def process_adblock(file_path: str) -> dict:
    results = {"urls": {}, "apps": {}, "content": {}}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return results

    for idx, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("!"):
            continue

        if line.startswith("||") and "^" in line:
            domain = line[2:].split("^")[0]
        else:
            domain = line

        url = domain if domain.startswith("http") else f"http://{domain}"
        sector = detect_sector(url)

        try:
            result = score_url(url, sector=sector)
        except Exception as e:
            print(f"Error scoring URL {url}: {e}")
            continue

        result.update({
            "sector": sector,
            "threat_label": "phishing",
            "source": "adblock",
            "file_name": os.path.basename(file_path),
            "file_type": "adblock",
            "collected_at": datetime.utcnow().isoformat() + "Z"
        })

        results["urls"][url] = result

        if idx % 100 == 0:
            print(f"  Processed {idx} lines in {os.path.basename(file_path)}")

    return results

# -------- Process Feed TXT ----------
def process_feed(file_path: str) -> dict:
    results = {"urls": {}, "apps": {}, "content": {}}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return results

    for idx, line in enumerate(lines, 1):
        url = line.strip()
        if not url or url.startswith("#"):
            continue

        sector = detect_sector(url)
        typ = classify_type(url)

        try:
            if typ == "app":
                result = score_app(url, platform="android", sector=sector)
            elif typ == "content":
                result = score_content(url, sector=sector)
            else:
                result = score_url(url, sector=sector)
        except Exception as e:
            print(f"Error scoring URL {url}: {e}")
            continue

        result.update({
            "sector": sector,
            "threat_label": "phishing",
            "source": "feed.txt",
            "file_name": os.path.basename(file_path),
            "file_type": "txt",
            "collected_at": datetime.utcnow().isoformat() + "Z"
        })

        results[typ + "s"][url] = result

        if idx % 100 == 0:
            print(f"  Processed {idx} lines in {os.path.basename(file_path)}")

    return results

# -------- Master Pipeline ----------
def process_files() -> dict:
    schema = {"urls": {}, "apps": {}, "content": {}}
    total_entries = 0
    start_time = time()

    files = glob.glob(os.path.join(DATA_DIR, "*"))
    print(f"Found {len(files)} files in {DATA_DIR}")

    for idx, file_path in enumerate(files, 1):
        filename = os.path.basename(file_path).lower()
        file_start = time()

        try:
            if filename.endswith(".json") and "urlhaus" in filename:
                res = process_urlhaus(file_path)
            elif "adblock" in filename:
                res = process_adblock(file_path)
            elif filename.endswith(".txt"):
                res = process_feed(file_path)
            else:
                print(f"[{idx}/{len(files)}] Skipping unknown file format: {filename}")
                continue

            for bucket in ["urls", "apps", "content"]:
                schema[bucket].update(res[bucket])

            file_entries = sum(len(v) for v in res.values())
            total_entries += file_entries
            elapsed = time() - file_start
            print(f"[{idx}/{len(files)}] Processed {file_entries} entries from {filename} in {elapsed:.2f}s (Total so far: {total_entries})")

        except Exception as e:
            print(f"Error processing {filename}: {e}")

    total_elapsed = time() - start_time
    print(f"\nAll files processed. Total entries: {total_entries}. Time taken: {total_elapsed:.2f}s")

    return schema

# -------- Run as script ----------
if __name__ == "__main__":
    schema = process_files()
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2)
        total = sum(len(v) for v in schema.values())
        print(f"\nFinal schema.json saved with {total} total entries")
    except Exception as e:
        print(f"Error writing {OUTPUT_FILE}: {e}")
