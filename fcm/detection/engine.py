from datetime import datetime
from detection.rules import score_from_reasons, status_from_score
from .features_url import extract_url_features
from .features_app import extract_app_features
from .features_content import extract_content_features

# ---------- URL ----------
def score_url(u: str) -> dict:
    f = extract_url_features(u)
    reasons = []

    if f["contains_at"]: reasons.append({"reason":"@ symbol in URL", "points": 15})
    if f["host_is_ip"]: reasons.append({"reason":"Host is an IP address", "points": 20})
    if f["hyphens"] >= 3: reasons.append({"reason":"Many hyphens in host", "points": 10})
    if f["length"] > 120: reasons.append({"reason":"Very long URL", "points": 15})
    elif f["length"] > 75: reasons.append({"reason":"Long URL", "points": 10})
    if f["is_punycode"]: reasons.append({"reason":"Punycode host", "points": 25})
    if f["tld_suspicious"]: reasons.append({"reason":f"Suspicious TLD .{f['tld']}", "points": 10})
    if f["subdomain_depth"] >= 4: reasons.append({"reason":"Deep subdomain nesting", "points": 10})
    if f["digits_ratio"] > 0.30: reasons.append({"reason":"High digits ratio", "points": 10})

    if f["word_hits"]:
        reasons.append({"reason":f"Suspicious words in path: {', '.join(f['word_hits'])}", "points": 10})

    # mild bonus if HTTPS and not otherwise risky
    if f["scheme"] == "https" and not reasons:
        reasons.append({"reason":"HTTPS present", "points": -5})

    score = score_from_reasons(reasons)
    return {
        "type": "url",
        "url": u,
        "features": f,
        "reasons": reasons,
        "score": score,
        "status": status_from_score(score),
        "timestamp": datetime.utcnow().isoformat()+"Z"
    }

# ---------- APP ----------
def score_app(u: str, platform="android") -> dict:
    f = extract_app_features(u, platform=platform)
    reasons = []
    if not f["is_official_store"]:
        reasons.append({"reason":"Not official app store", "points": 25})
    if f["direct_apk"]:
        reasons.append({"reason":"Direct APK download", "points": 30})
    if f["scam_hits"]:
        reasons.append({"reason":f"Scam keywords: {', '.join(f['scam_hits'])}", "points": 20})

    if f["is_official_store"] and not reasons:
        reasons.append({"reason":"Official store link", "points": -10})

    score = score_from_reasons(reasons)
    return {
        "type": "app",
        "url": u,
        "platform": platform,
        "features": f,
        "reasons": reasons,
        "score": score,
        "status": status_from_score(score),
        "timestamp": datetime.utcnow().isoformat()+"Z"
    }

# ---------- CONTENT ----------
def score_content(u: str) -> dict:
    f = extract_content_features(u)
    reasons = []
    if f["is_dangerous"]: reasons.append({"reason":f"Dangerous file type {f['ext']}", "points": 40})
    if f["has_bait_words"]: reasons.append({"reason":"Bait words in URL", "points": 10})
    if f["very_long_query"]: reasons.append({"reason":"Very long querystring", "points": 10})
    # If it's a known safe doc/image and nothing else raised flags, give a mild negative
    if (f["is_known_doc"] or f["is_image"]) and not reasons:
        reasons.append({"reason":"Known doc/image type", "points": -5})
    if not f["recognized_ext"]:
        reasons.append({"reason":"Unknown or missing extension", "points": 5})

    score = score_from_reasons(reasons)
    return {
        "type": "content",
        "url": u,
        "features": f,
        "reasons": reasons,
        "score": score,
        "status": status_from_score(score),
        "timestamp": datetime.utcnow().isoformat()+"Z"
    }
