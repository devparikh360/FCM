from urllib.parse import urlparse

SCAM_WORDS = {"mod","crack","premium","free-download","apk","mirror","patch","hack"}

def extract_app_features(u: str, platform: str = "android") -> dict:
    """
    For android, official is play.google.com.
    For iOS, official is apps.apple.com (not implemented here yet).
    """
    try:
        p = urlparse(u)
    except Exception:
        p = urlparse("")
    host = (p.hostname or "").lower()
    path = (p.path or "") + ("?" + p.query if p.query else "")
    is_official = False

    if platform == "android":
        is_official = ("play.google.com" in host)
    elif platform == "ios":
        is_official = ("apps.apple.com" in host)

    scam_hits = [w for w in SCAM_WORDS if w in path.lower() or w in host]

    direct_apk = (u.lower().endswith(".apk") or ".apk?" in u.lower())

    return {
        "host": host,
        "is_official_store": is_official,
        "scam_hits": scam_hits,
        "direct_apk": direct_apk,
        "platform": platform,
    }
