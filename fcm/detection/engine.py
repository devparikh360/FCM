# detection/engine.py
from datetime import datetime
from detection.rules import score_from_reasons, status_from_score
from .features_url import extract_url_features, is_valid_url
from .features_app import extract_app_features
from .features_content import extract_content_features
import os
import numpy as np
import xgboost as xgb
import json
import requests
import tldextract
from urllib.parse import urlparse

# --- Load ML model ---
ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
MODEL_PATH = os.path.join(ROOT_DIR, "xgboost_model.json")
FEATURES_PATH = os.path.join(ROOT_DIR, "feature_columns.json")

ml_model = None
TRAINED_FEATURES = []

if os.path.exists(MODEL_PATH):
    ml_model = xgb.XGBClassifier()
    ml_model.load_model(MODEL_PATH)
    if os.path.exists(FEATURES_PATH):
        with open(FEATURES_PATH, "r") as f:
            TRAINED_FEATURES = json.load(f)
    else:
        try:
            TRAINED_FEATURES = ml_model.get_booster().feature_names
        except Exception:
            TRAINED_FEATURES = []
else:
    print("⚠️ ML model not found. Only rule-based scoring will be used.")

# --- Load legit domains (normalized to registrable domain: domain.tld) ---
LEGIT_FILE = os.path.join(ROOT_DIR, "data", "leg.txt")

def load_legit_domains(path):
    s = set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip().lower()
                if not line:
                    continue
                # strip scheme if present and take hostname
                try:
                    p = urlparse(line if line.startswith(("http://","https://")) else "http://" + line)
                    host = (p.hostname or line).lower()
                except Exception:
                    host = line
                if host.startswith("www."):
                    host = host[4:]
                ext = tldextract.extract(host)
                if ext.domain and ext.suffix:
                    s.add(f"{ext.domain}.{ext.suffix}")
                else:
                    s.add(host)
    except Exception as e:
        print("Could not load legit domains from", path, ":", e)
    return s

LEGIT_DOMAINS = load_legit_domains(LEGIT_FILE)

# --- Helpers ---
def apply_sector_boost(reasons, sector):
    if sector in ("banking", "finance", "payment"):
        reasons.append({"reason": "Banking/finance related → higher risk", "points": 10})
    elif sector in ("social", "messaging", "email"):
        reasons.append({"reason": "Social/messaging related → phishing prone", "points": 5})
    return reasons

def apply_ml_score(features, reasons):
    """
    Append ML probability to reasons as a single, non-accusatory entry:
      "ML probability: 0.42" with points = int(prob*100)
    (We no longer append "ML model flagged as suspicious".)
    """
    if ml_model is None or not TRAINED_FEATURES:
        return reasons

    X_vec = []
    for f_name in TRAINED_FEATURES:
        val = features.get(f_name, 0)
        if isinstance(val, list):
            # collapse lists -> string -> hashed number
            val = "_".join([str(v) for v in val])
            val = hash(val) % 1000
        elif isinstance(val, str):
            val = hash(val) % 1000
        elif isinstance(val, bool):
            val = int(val)
        elif isinstance(val, dict):
            # don't attempt to serialize large dicts — use fallback 0
            val = 0
        elif val is None:
            val = 0
        X_vec.append(val)

    X_vec = np.array([X_vec])
    try:
        ml_prob = float(ml_model.predict_proba(X_vec)[0][1])
        ml_points = int(ml_prob * 100)
        reasons.append({"reason": f"ML probability: {ml_prob:.2f}", "points": ml_points})
    except Exception as e:
        print("⚠️ ML model scoring failed:", e)
        reasons.append({"reason": "ML scoring failed", "points": 0})

    return reasons

# ------- ports / reachability ----------------
def check_uncommon_port(parsed) -> bool:
    if parsed is None or parsed.port is None:
        return False
    return parsed.port not in (80, 443)

#import requests

def url_exists(u: str, timeout: int = 5) -> bool:
    """Check if a URL is reachable (try HEAD first, then GET fallback)."""
    try:
        # Ensure scheme
        url_to_check = u if u.startswith(("http://", "https://")) else "http://" + u
        
        # First try HEAD
        try:
            resp = requests.head(url_to_check, allow_redirects=True, timeout=timeout)
            if 200 <= resp.status_code < 400:
                return True
        except requests.RequestException:
            pass
        
        # Fallback to GET if HEAD fails
        resp = requests.get(url_to_check, allow_redirects=True, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        return 200 <= resp.status_code < 400
    
    except Exception:
        return False


def get_registrable_domain(u: str) -> str:
    """Return domain.tld for the passed URL/host (normalized, lower)."""
    try:
        p = urlparse(u if u.startswith(("http://","https://")) else "http://" + u)
        host = (p.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return host
    except Exception:
        return ""

# ---------- URL scoring ----------
def score_input(u: str, sector="general") -> dict:
    if not is_valid_url(u):
        return {
            "type": "unknown",
            "input": u,
            "sector": sector,
            "features": {},
            "reasons": [{"reason": "Input is not a valid URL", "points": 50}],
            "score": 99,
            "status": "High Risk",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    return score_url(u, sector)

def score_url(u: str, sector="general") -> dict:
    f = extract_url_features(u)
    reasons = []

    # Normalize host for legit check
    host = f.get("host", "").lower().strip()
    if host.startswith("www."):
        host = host[4:]

    # --- LOAD LEGIT LIST ---
    legit_domains = []
    legit_file = os.path.join(ROOT_DIR, "legit.txt")
    if os.path.exists(legit_file):
        with open(legit_file, "r") as lf:
            legit_domains = [line.strip().lower() for line in lf if line.strip()]

    # --- LEGIT EXACT MATCH ---
    is_legit = host in legit_domains
    if is_legit:
        reasons.append({"reason": "Domain marked as legit", "points": -30})

    # --- 2️⃣ HIGH SEVERITY CHECKS ---
    if f.get("host_is_ip", False):
        reasons.append({"reason": "Host is an IP address", "points": 30})
    if f.get("uncommon_port", False):
        reasons.append({"reason": f"Uncommon port {f.get('port')}", "points": 20})

    # --- 3️⃣ PUNYCODE / HOMOGRAPH ---
    if "punycode" in f:
        p = f["punycode"]
        if p.get("is_punycode", False):
            reason_text = "Suspicious Punycode host"
            if p.get("contains_homoglyphs", False):
                reason_text += " with homoglyphs"
                points = p.get("punycode_severity", 20)
            else:
                points = p.get("punycode_severity", 15)
            reasons.append({"reason": reason_text, "points": points})

    # --- 4️⃣ BRAND SIMILARITY ---
    # Always run brand similarity even if domain is legit
    brand_sim = f.get("brand_similarity", {})
    if isinstance(brand_sim, dict):
        for brand, dist in brand_sim.items():
            if dist <= 2:
                reasons.append({
                    "reason": f"Domain similar to brand '{brand}'",
                    "points": 35 if dist == 1 else 25
                })
    elif f.get("brand_similarity_score", 99) <= 2:
        reasons.append({"reason": "Brand similarity detected", "points": 20})

    # --- 5️⃣ TLD CHECKS ---
    if f.get("tld_suspicious", False):
        reasons.append({"reason": f"Suspicious TLD .{f.get('tld','')}", "points": 20})

    # --- 6️⃣ DOMAIN AGE ---
    age = f.get("domain_age_days", -1)
    if 0 <= age < 30:
        reasons.append({"reason": f"Domain very new ({age} days)", "points": 30})
    elif 0 <= age < 180:
        reasons.append({"reason": f"Domain fairly new ({age} days)", "points": 15})

    # --- 7️⃣ SSL CHECK ---
    if f.get("scheme") == "https" and not f.get("ssl_valid", 1):
        reasons.append({"reason": "HTTPS but invalid/expired SSL", "points": 15})

    # --- 8️⃣ MEDIUM SEVERITY CHECKS ---
    if f.get("contains_at", False):
        reasons.append({"reason": "@ symbol in URL", "points": 15})
    if f.get("hyphens", 0) >= 3:
        reasons.append({"reason": "Many hyphens in host", "points": 10})
    if f.get("subdomain_depth", 0) >= 4:
        reasons.append({"reason": "Deep subdomain nesting", "points": 15})

    digits_ratio = f.get("digits_ratio", 0)
    if digits_ratio > 0.5:
        reasons.append({"reason": "Host mostly digits", "points": 25})
    elif digits_ratio > 0.3:
        reasons.append({"reason": "High digits ratio in host", "points": 15})

    length = f.get("length", 0)
    if length > 120:
        reasons.append({"reason": "Very long URL", "points": 20})
    elif length > 75:
        reasons.append({"reason": "Long URL", "points": 10})

    # --- 9️⃣ REDIRECTS ---
    if f.get("redirect_count", 0) > 3:
        reasons.append({"reason": f"Excessive redirects ({f['redirect_count']})", "points": 10})

    # --- 🔟 NLP / PHISHING CHECKS ---
    nlp_score = f.get("nlp_phish_score", 0)
    if nlp_score > 0.6:
        reasons.append({"reason": "Phishing language detected (NLP)", "points": 25})
    elif nlp_score > 0.3:
        reasons.append({"reason": "Suspicious wording (NLP)", "points": 10})

    # --- 11️⃣ SAFE BONUSES ---
    if f.get("scheme") == "https" and not reasons:
        reasons.append({"reason": "HTTPS present (safe signal)", "points": -5})
    if age > 365 and not reasons:
        reasons.append({"reason": "Domain older than 1 year (trust signal)", "points": -5})

    # --- 12️⃣ SECTOR SCORING ---
    reasons = apply_sector_boost(reasons, sector)

    # --- 13️⃣ URL REACHABILITY (LAST STEP) ---
    if not url_exists(u):
        reasons.append({"reason": "URL not reachable", "points": 40})

    # --- 14️⃣ FINAL SCORE ---
    score = score_from_reasons(reasons)
    status = status_from_score(score)

    return {
        "type": "url",
        "url": u,
        "sector": sector,
        "features": f,
        "reasons": reasons,
        "score": score,
        "status": status,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


# ---------- APP & CONTENT scoring (unchanged logic but kept here for completeness) ----------
def score_app(u: str, platform="android", sector="general") -> dict:
    f = extract_app_features(u, platform=platform)
    reasons = []

    if f.get("direct_apk"):
        reasons.append({"reason": "Direct APK download (bypass store)", "points": 40})
    if f.get("direct_ipa", False):
        reasons.append({"reason": "Direct IPA download (bypass store)", "points": 40})

    if not f.get("is_official_store", True):
        reasons.append({"reason": "Not official app store", "points": 25})
    if f.get("scam_hits"):
        reasons.append({"reason": f"Scam keywords: {', '.join(f['scam_hits'])}", "points": 20})
    if f.get("shortened", False):
        reasons.append({"reason": "Shortened URL (bit.ly/tinyurl/t.co)", "points": 15})
    if f.get("contains_id_param", False) and not f.get("is_official_store", True):
        reasons.append({"reason": "Contains suspicious ID parameter", "points": 10})

    if f.get("length", 0) > 100:
        reasons.append({"reason": "Very long URL", "points": 10})
    elif f.get("length", 0) < 15:
        reasons.append({"reason": "Extremely short URL", "points": 10})

    if not f.get("https", False):
        reasons.append({"reason": "Non-HTTPS URL", "points": 15})

    if platform == "android" and f.get("direct_ipa", False):
        reasons.append({"reason": "iOS IPA on Android platform", "points": 20})
    if platform == "ios" and f.get("direct_apk", False):
        reasons.append({"reason": "Android APK on iOS platform", "points": 20})

    if f.get("is_official_store", False) and not reasons:
        reasons.append({"reason": "Official store link (safe)", "points": -15})

    reasons = apply_sector_boost(reasons, sector)
    reasons = apply_ml_score(f, reasons)

    score = score_from_reasons(reasons)
    return {
        "type": "app",
        "url": u,
        "platform": platform,
        "sector": sector,
        "features": f,
        "reasons": reasons,
        "score": score,
        "status": status_from_score(score),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

def score_content(u: str, sector="general") -> dict:
    f = extract_content_features(u)
    reasons = []

    if f.get("is_dangerous"):
        reasons.append({"reason": f"Dangerous file type {f.get('ext')}", "points": 40})
    if f.get("suspicious_patterns"):
        reasons.append({"reason": "Suspicious pattern detected (login/password/numeric)", "points": 25})
    if f.get("digits_in_filename_ratio", 0) > 0.4:
        reasons.append({"reason": "High digit ratio in filename", "points": 20})
    if f.get("special_chars_in_filename", 0) >= 3:
        reasons.append({"reason": "Multiple special characters in filename", "points": 15})

    if f.get("has_bait_words"):
        reasons.append({"reason": "Bait words in URL", "points": 15})
    if f.get("very_long_query"):
        reasons.append({"reason": "Very long querystring", "points": 15})
    if f.get("contains_double_ext"):
        reasons.append({"reason": "Filename has double extensions", "points": 10})

    if not f.get("recognized_ext"):
        reasons.append({"reason": "Unknown or missing extension", "points": 5})

    if (f.get("is_known_doc") or f.get("is_image")) and not reasons:
        reasons.append({"reason": "Known doc/image type", "points": -10})

    reasons = apply_sector_boost(reasons, sector)
    reasons = apply_ml_score(f, reasons)

    score = score_from_reasons(reasons)
    status = status_from_score(score)

    return {
        "type": "content",
        "url": u,
        "sector": sector,
        "features": f,
        "reasons": reasons,
        "score": score,
        "status": status,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
