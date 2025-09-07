import re
import tldextract
from urllib.parse import urlparse

OFFICIAL_STORES = [
    "play.google.com",
    "apps.apple.com",
    "microsoft.com/store"
]

SCAM_KEYWORDS = [
    "mod", "crack", "hack", "unlimited", "freecoins",
    "premiumfree", "apkdownload", "patch", "serial",
    "nulled", "keygen", "proversion"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd", "shorte.st", "ow.ly"
]

def extract_app_features(u: str, platform="android") -> dict:
    low_u = u.lower()
    parsed = urlparse(u)
    host = parsed.hostname or ""
    ext = tldextract.extract(u)

    # Core features
    features = {
        "platform": platform,
        "is_official_store": any(store in low_u for store in OFFICIAL_STORES),
        "direct_apk": low_u.endswith(".apk"),
        "direct_ipa": low_u.endswith(".ipa"),
        "scam_hits": [w for w in SCAM_KEYWORDS if w in low_u],
        "length": len(u),
        "contains_id_param": "id=" in low_u,
        "shortened": any(s in low_u for s in URL_SHORTENERS),
        "https": u.startswith("https://"),
        "subdomain_depth": host.count("."),
        "hyphens_in_domain": host.count("-"),
        "digits_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
        "path_depth": parsed.path.count("/"),
        "query_length": len(parsed.query),
    }

    # Store impersonation (fake Google Play or Apple App Store domains)
    features["fake_store_lookalike"] = (
        ("play" in ext.domain and "google" in ext.subdomain) or
        ("apple" in ext.domain and "apps" in ext.subdomain)
    )

    # Suspicious domain TLDs often used for fake APK hosting
    SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "buzz"}
    features["suspicious_tld"] = ext.suffix in SUSPICIOUS_TLDS

    # Check if URL is using unusual ports (rare for app stores)
    features["port_present"] = parsed.port is not None

    return features
