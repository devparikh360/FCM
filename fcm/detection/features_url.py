import re
import ssl
import socket
import whois
import requests
import idna
import tldextract
from datetime import datetime
from urllib.parse import urlparse
from Levenshtein import distance as levenshtein

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz"}
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "secure",
    "banking", "account", "webscr", "paypal", "free",
    "bonus", "gift", "prize", "lottery", "credit"
]
BRAND_KEYWORDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook"]

import whois

def get_domain_age(domain: str) -> int:
    #try:
       # w = whois.whois(domain)
       # if w.creation_date:
         #   if isinstance(w.creation_date, list):
        #        cd = w.creation_date[0]
       #     else:
      #          cd = w.creation_date
     #       age_days = (datetime.utcnow() - cd).days
    #        return age_days
   #     return -1
  #  except Exception:
    return -1  # fail-safe value


def get_ssl_validity(domain: str) -> bool:
    """Check if SSL cert exists/valid"""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return True if cert else False
    except Exception:
        return False

def detect_homograph(domain: str) -> bool:
    """Check for Unicode homograph tricks"""
    try:
        ascii_version = idna.encode(domain).decode()
        return domain != ascii_version
    except Exception:
        return False

def brand_similarity(domain: str) -> dict:
    """Check similarity to known brands"""
    results = {}
    for brand in BRAND_KEYWORDS:
        dist = levenshtein(domain, brand)
        if dist <= 2:  # very close typo
            results[brand] = dist
    return results

def count_redirects(url: str) -> int:
    """Follow redirects and count chain length"""
    try:
        r = requests.get(url, timeout=3, allow_redirects=True)
        return len(r.history)
    except Exception:
        return 0

def extract_url_features(u: str) -> dict:
    try:
        parsed = urlparse(u)
    except Exception:
        return {"error": "invalid_url"}

    host = parsed.hostname or ""
    ext = tldextract.extract(u)
    domain = ext.domain
    tld = ext.suffix
    path = parsed.path or ""

    features = {
        # Basic structural features
        "scheme": parsed.scheme,
        "contains_at": "@" in u,
        "host_is_ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)),
        "hyphens": host.count("-"),
        "length": len(u),
        "is_punycode": host.startswith("xn--"),
        "tld": tld,
        "tld_suspicious": tld in SUSPICIOUS_TLDS,
        "subdomain_depth": host.count("."),
        "digits_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
        "path_length": len(path),
        "query_length": len(parsed.query),
        "fragment_present": bool(parsed.fragment),
        "port_present": parsed.port is not None,
        "word_hits": [w for w in SUSPICIOUS_WORDS if w in u.lower()],

        # Advanced features
        "domain_age_days": get_domain_age(host),
        "ssl_valid": get_ssl_validity(host) if parsed.scheme == "https" else False,
        "homograph": detect_homograph(host),
        "brand_similarity": brand_similarity(host),
        "redirect_count": count_redirects(u),
    }
    return features
