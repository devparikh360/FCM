from datetime import datetime
from detection.rules import score_from_reasons, status_from_score
from .features_url import extract_url_features
from .features_app import extract_app_features
from .features_content import extract_content_features
import os
import numpy as np
import xgboost as xgb
import json
from .features_url import extract_url_features, is_valid_url



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
        except:
            TRAINED_FEATURES = []
else:
    print("⚠️ ML model not found. Only rule-based scoring will be used.")

# --- helper: apply sector boost ---
def apply_sector_boost(reasons, sector):
    if sector in ("banking", "finance", "payment"):
        reasons.append({"reason": "Banking/finance related → higher risk", "points": 10})
    elif sector in ("social", "messaging", "email"):
        reasons.append({"reason": "Social/messaging related → phishing prone", "points": 5})
    return reasons

# --- helper: apply ML score ---
def apply_ml_score(features, reasons):
    if ml_model is None or not TRAINED_FEATURES:
        return reasons

    X_vec = []
    for f_name in TRAINED_FEATURES:
        val = features.get(f_name, 0)

        if isinstance(val, list):
            val = "_".join([str(v) for v in val])
        if isinstance(val, str):
            val = hash(val) % 1000
        elif isinstance(val, bool):
            val = int(val)
        elif val is None:
            val = 0
        X_vec.append(val)

    X_vec = np.array([X_vec])

    try:
        ml_prob = ml_model.predict_proba(X_vec)[0][1]

        print("ML input vector:", X_vec)
        print("ML predicted probability:", ml_prob)

        ml_points = int(ml_prob * 100)
        if ml_points > 0:
            reasons.append({
                "reason": "ML model flagged as suspicious",
                "points": ml_points
            })
    except Exception as e:
        reasons.append({"reason": "ML scoring failed", "points": 0})
        print("⚠️ ML model scoring failed:", e)

    return reasons

#-------ports----------------

def check_uncommon_port(parsed) -> bool:
    if parsed.port is None:
        return False
    return parsed.port not in [80, 443]

from datetime import datetime
from urllib.parse import urlparse

# ---------- URL scoring ----------
def score_input(u: str, sector="general") -> dict:
    """
    Decide scoring based on whether input is a valid URL
    """
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

    # valid URL → pass to your existing scoring engine
    return score_url(u, sector)

def score_url(u: str, sector="general") -> dict:
    f = extract_url_features(u)
    reasons = []

    # --- 1️⃣ WHITELIST / SAFE DOMAINS ---
    def score_url(u: str, sector="general") -> dict:
        f = extract_url_features(u)
        reasons = []

    is_legit=f.get("is_legit", False)

    # --- 1️⃣ WHITELIST / SAFE DOMAINS (hard override) ---
    if is_legit:
        reasons.append({"reason": "Domain is in whitelist (legit)", "points": -30})
        return {
            "type": "url",
            "url": u,
            "sector": sector,
            "features": f,
            "reasons": reasons,
            "score": 0,   # force SAFE
            "status": "Safe",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

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

    # --- 4️⃣ BRAND SIMILARITY / SUSPICIOUS WORDS (ONLY IF NOT LEGIT) ---
    if not is_legit:
        brand_sim = f.get("brand_similarity", {})
        if isinstance(brand_sim, dict):
            for brand, dist in brand_sim.items():
                if dist <= 2:
                    reasons.append({
                        "reason": f"Domain similar to brand '{brand}'",
                        "points": 25 if dist == 1 else 15
                    })
        elif f.get("brand_similarity_score", 99) <= 2:
            reasons.append({"reason": "Brand similarity detected", "points": 10})

        if f.get("word_hits_count", 0) > 0:
            reasons.append({
                "reason": f"Suspicious words in URL: {f['word_hits']}",
                "points": 10
            })

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

    # --- 10️⃣ NLP / PHISHING CHECKS ---
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

    # --- 12️⃣ SECTOR + ML SCORING ---
    reasons = apply_sector_boost(reasons, sector)
    reasons = apply_ml_score(f, reasons)

    # --- 13️⃣ FINAL SCORE ---
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

# ---------- APP ----------
def score_app(u: str, platform="android", sector="general") -> dict:
    f = extract_app_features(u, platform=platform)
    reasons = []

    if f["direct_apk"]:
        reasons.append({"reason": "Direct APK download (bypass store)", "points": 40})
    if f.get("direct_ipa", False):
        reasons.append({"reason": "Direct IPA download (bypass store)", "points": 40})

    if not f["is_official_store"]:
        reasons.append({"reason": "Not official app store", "points": 25})
    if f["scam_hits"]:
        reasons.append({"reason": f"Scam keywords: {', '.join(f['scam_hits'])}", "points": 20})
    if f.get("shortened", False):
        reasons.append({"reason": "Shortened URL (bit.ly/tinyurl/t.co)", "points": 15})
    if f.get("contains_id_param", False) and not f["is_official_store"]:
        reasons.append({"reason": "Contains suspicious ID parameter", "points": 10})

    if f["length"] > 100:
        reasons.append({"reason": "Very long URL", "points": 10})
    elif f["length"] < 15:
        reasons.append({"reason": "Extremely short URL", "points": 10})

    if not f.get("https", False):
        reasons.append({"reason": "Non-HTTPS URL", "points": 15})

    if platform == "android" and f.get("direct_ipa", False):
        reasons.append({"reason": "iOS IPA on Android platform", "points": 20})
    if platform == "ios" and f.get("direct_apk", False):
        reasons.append({"reason": "Android APK on iOS platform", "points": 20})

    if f["is_official_store"] and not reasons:
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

# ---------- CONTENT ----------
def score_content(u: str, sector="general") -> dict:
    f = extract_content_features(u)
    reasons = []

    if f["is_dangerous"]:
        reasons.append({"reason": f"Dangerous file type {f['ext']}", "points": 40})
    if f["suspicious_patterns"]:
        reasons.append({"reason": "Suspicious pattern detected (login/password/numeric)", "points": 25})
    if f["digits_in_filename_ratio"] > 0.4:
        reasons.append({"reason": "High digit ratio in filename", "points": 20})
    if f["special_chars_in_filename"] >= 3:
        reasons.append({"reason": "Multiple special characters in filename", "points": 15})

    if f["has_bait_words"]:
        reasons.append({"reason": "Bait words in URL", "points": 15})
    if f["very_long_query"]:
        reasons.append({"reason": "Very long querystring", "points": 15})
    if f["contains_double_ext"]:
        reasons.append({"reason": "Filename has double extensions", "points": 10})

    if not f["recognized_ext"]:
        reasons.append({"reason": "Unknown or missing extension", "points": 5})

    if (f["is_known_doc"] or f["is_image"]) and not reasons:
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
