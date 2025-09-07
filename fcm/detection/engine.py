from datetime import datetime
from detection.rules import score_from_reasons, status_from_score
from .features_url import extract_url_features
from .features_app import extract_app_features
from .features_content import extract_content_features
import os
import numpy as np
import xgboost as xgb
import json

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
        # fallback to booster feature names
        try:
            TRAINED_FEATURES = ml_model.get_booster().feature_names
        except:
            TRAINED_FEATURES = []
else:
    print("ML model not found. Only rule-based scoring will be used.")

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

    # --- Prepare input vector in correct feature order ---
    X_vec = []
    for f_name in TRAINED_FEATURES:
        val = features.get(f_name, 0)

        # --- Convert types to numeric ---
        if isinstance(val, list):
            val = "_".join([str(v) for v in val])  # lists -> joined string
        if isinstance(val, str):
            val = hash(val) % 1000  # consistent numeric encoding
        elif isinstance(val, bool):
            val = int(val)
        elif val is None:
            val = 0
        X_vec.append(val)

    X_vec = np.array([X_vec])

    try:
        ml_prob = ml_model.predict_proba(X_vec)[0][1]  # probability of fraudulent

        print("ML input vector:", X_vec)
        print("ML predicted probability:", ml_prob)

        # Scale to 0–50 points, but make sure small probabilities don't get stuck at 0
        ml_points = max(0, min(50, int(ml_prob * 50)))

        reasons.append({
            "reason": f"ML model prediction ({ml_prob:.2f} probability)",
            "points": ml_points
        })
    except Exception as e:
        reasons.append({"reason": "ML scoring failed", "points": 0})
        print("⚠️ ML model scoring failed:", e)

    return reasons


# ---------- URL ----------
def score_url(u: str, sector="general") -> dict:
    f = extract_url_features(u)
    reasons = []

    # High severity
    if f["host_is_ip"]:
        reasons.append({"reason": "Host is an IP address", "points": 30})
    if f["is_punycode"]:
        reasons.append({"reason": "Punycode host", "points": 25})
    if f["tld_suspicious"]:
        reasons.append({"reason": f"Suspicious TLD .{f['tld']}", "points": 20})
    if f["homograph"]:
        reasons.append({"reason": "Homograph domain detected", "points": 25})

    # Domain age
    if 0 <= f["domain_age_days"] < 30:
        reasons.append({"reason": f"Domain very new ({f['domain_age_days']} days)", "points": 30})
    elif 0 <= f["domain_age_days"] < 180:
        reasons.append({"reason": f"Domain fairly new ({f['domain_age_days']} days)", "points": 15})

    # SSL
    if f["scheme"] == "https" and not f["ssl_valid"]:
        reasons.append({"reason": "HTTPS but invalid/expired SSL", "points": 15})

    # Brand similarity
    if f["brand_similarity"]:
        for brand, dist in f["brand_similarity"].items():
            reasons.append({
                "reason": f"Domain similar to brand '{brand}' (edit distance {dist})",
                "points": 25 if dist == 1 else 15
            })

    # Redirects
    if f["redirect_count"] > 3:
        reasons.append({"reason": f"Excessive redirects ({f['redirect_count']})", "points": 10})

    # Medium severity
    if f["contains_at"]:
        reasons.append({"reason": "@ symbol in URL", "points": 15})
    if f["hyphens"] >= 3:
        reasons.append({"reason": "Many hyphens in host", "points": 10})
    if f["subdomain_depth"] >= 4:
        reasons.append({"reason": "Deep subdomain nesting", "points": 15})
    if f["digits_ratio"] > 0.3:
        reasons.append({"reason": "High digits ratio in URL", "points": 15})

    # Length
    if f["length"] > 120:
        reasons.append({"reason": "Very long URL", "points": 20})
    elif f["length"] > 75:
        reasons.append({"reason": "Long URL", "points": 10})

    # Suspicious words
    if f["word_hits"]:
        reasons.append({"reason": f"Suspicious words in path: {', '.join(f['word_hits'])}", "points": 20})

    # Safe bonuses
    if f["scheme"] == "https" and not reasons:
        reasons.append({"reason": "HTTPS present (safe signal)", "points": -5})
    if f["domain_age_days"] > 365 and not reasons:
        reasons.append({"reason": "Domain older than 1 year (trust signal)", "points": -5})

    # Sector boost
    reasons = apply_sector_boost(reasons, sector)

    # ML integration
    reasons = apply_ml_score(f, reasons)

    score = score_from_reasons(reasons)
    return {
        "type": "url",
        "url": u,
        "sector": sector,
        "features": f,
        "reasons": reasons,
        "score": score,
        "status": status_from_score(score),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

# ---------- APP ----------
def score_app(u: str, platform="android", sector="general") -> dict:
    f = extract_app_features(u, platform=platform)
    reasons = []

    # High severity
    if f["direct_apk"]:
        reasons.append({"reason": "Direct APK download (bypass store)", "points": 40})
    if f.get("direct_ipa", False):
        reasons.append({"reason": "Direct IPA download (bypass store)", "points": 40})

    # Medium severity
    if not f["is_official_store"]:
        reasons.append({"reason": "Not official app store", "points": 25})
    if f["scam_hits"]:
        reasons.append({"reason": f"Scam keywords: {', '.join(f['scam_hits'])}", "points": 20})
    if f.get("shortened", False):
        reasons.append({"reason": "Shortened URL (bit.ly/tinyurl/t.co)", "points": 15})
    if f.get("contains_id_param", False) and not f["is_official_store"]:
        reasons.append({"reason": "Contains suspicious ID parameter", "points": 10})

    # URL length
    if f["length"] > 100:
        reasons.append({"reason": "Very long URL", "points": 10})
    elif f["length"] < 15:
        reasons.append({"reason": "Extremely short URL", "points": 10})

    # HTTPS
    if not f.get("https", False):
        reasons.append({"reason": "Non-HTTPS URL", "points": 15})

    # Platform mismatch
    if platform == "android" and f.get("direct_ipa", False):
        reasons.append({"reason": "iOS IPA on Android platform", "points": 20})
    if platform == "ios" and f.get("direct_apk", False):
        reasons.append({"reason": "Android APK on iOS platform", "points": 20})

    # Safe bonus
    if f["is_official_store"] and not reasons:
        reasons.append({"reason": "Official store link (safe)", "points": -15})

    # Sector boost
    reasons = apply_sector_boost(reasons, sector)

    # ML integration
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

    # High severity
    if f["is_dangerous"]:
        reasons.append({"reason": f"Dangerous file type {f['ext']}", "points": 40})
    if f["suspicious_patterns"]:
        reasons.append({"reason": "Suspicious pattern detected (login/password/numeric)", "points": 25})
    if f["digits_in_filename_ratio"] > 0.4:
        reasons.append({"reason": "High digit ratio in filename", "points": 20})
    if f["special_chars_in_filename"] >= 3:
        reasons.append({"reason": "Multiple special characters in filename", "points": 15})

    # Medium severity
    if f["has_bait_words"]:
        reasons.append({"reason": "Bait words in URL", "points": 15})
    if f["very_long_query"]:
        reasons.append({"reason": "Very long querystring", "points": 15})
    if f["contains_double_ext"]:
        reasons.append({"reason": "Filename has double extensions", "points": 10})

    # Low severity
    if not f["recognized_ext"]:
        reasons.append({"reason": "Unknown or missing extension", "points": 5})

    # Safe bonus
    if (f["is_known_doc"] or f["is_image"]) and not reasons:
        reasons.append({"reason": "Known doc/image type", "points": -10})

    # Sector boost
    reasons = apply_sector_boost(reasons, sector)

    # ML integration
    reasons = apply_ml_score(f, reasons)

    score = score_from_reasons(reasons)
    return {
        "type": "content",
        "url": u,
        "sector": sector,
        "features": f,
        "reasons": reasons,
        "score": score,
        "status": status_from_score(score),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
