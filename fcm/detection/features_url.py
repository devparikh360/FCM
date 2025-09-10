# detection/features_url.py
import os
import re
import ssl
import socket
import requests
import idna
import tldextract
from datetime import datetime
from urllib.parse import urlparse
from Levenshtein import distance as levenshtein

# ----- Config / lists -----
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz"}
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "win", "password", "update", "bank", "account",
    "secure", "confirm", "banking", "webscr", "paypal", "free", "bonus", "gift",
    "prize", "lottery", "credit"
]
BRAND_KEYWORDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook"]

# ----- Helper: normalize and load whitelist (leg.txt) ----- 
MODULE_DIR = os.path.dirname(__file__)
LEG_FILE = os.path.normpath(os.path.join(MODULE_DIR, "..", "data", "leg.txt"))

def normalize_domain(domain: str) -> str:
    """Return registrable domain (domain.suffix) or empty string."""
    if not domain:
        return ""
    domain = domain.strip().lower()
    # strip scheme and trailing slash and possible credentials
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]
    domain = domain.split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    try:
        ext = tldextract.extract(domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    return domain

try:
    with open(LEG_FILE, "r", encoding="utf-8") as fh:
        LEGIT_DOMAINS = {normalize_domain(line) for line in fh if line.strip()}
except Exception:
    LEGIT_DOMAINS = set()

# ----- Whitelist check: only exact base or www.base allowed -----
def is_legit_domain(host_or_url: str) -> bool:
    """
    Return True only if the host is exactly 'domain.tld' or 'www.domain.tld'
    and that registrable domain is present in LEGIT_DOMAINS.
    """
    if not host_or_url:
        return False
    host_or_url = host_or_url.strip().lower()
    # ensure we operate on host part
    if host_or_url.startswith("http://") or host_or_url.startswith("https://"):
        try:
            host_or_url = urlparse(host_or_url).hostname or host_or_url
        except Exception:
            pass
    # extract subdomain/domain/tld
    ext = tldextract.extract(host_or_url)
    if not ext.domain or not ext.suffix:
        return False
    base = f"{ext.domain}.{ext.suffix}"
    sub = ext.subdomain  # may be "" or "www" or other subdomains
    if base not in LEGIT_DOMAINS:
        return False
    # allow exact base or www.base only
    if sub == "" or sub == "www":
        return True
    return False

# ----- Small helpers -----
def get_domain_age(domain: str) -> int:
    return -1

def get_ssl_validity(domain: str) -> bool:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return bool(cert)
    except Exception:
        return False

def detect_homograph(domain: str) -> bool:
    try:
        ascii_version = idna.encode(domain).decode()
        return domain != ascii_version
    except Exception:
        return False

def brand_similarity_score(domain: str) -> dict:
    return {brand: levenshtein(domain, brand) for brand in BRAND_KEYWORDS}

def count_redirects(url: str) -> int:
    try:
        r = requests.get(url, timeout=3, allow_redirects=True)
        return len(r.history)
    except Exception:
        return 0

def check_punycode(host: str) -> dict:
    result = {"is_punycode": 0, "decoded_host": host, "contains_homoglyphs": 0, "punycode_severity": 0}
    try:
        if host and "xn--" in host:
            result["is_punycode"] = 1
            decoded = idna.decode(host)
            result["decoded_host"] = decoded
            homoglyph_map = {"а":"a","е":"e","о":"o","і":"i","ѕ":"s","р":"p","Ɩ":"l","ʘ":"o","ꞵ":"b"}
            for ch in decoded:
                if ch in homoglyph_map:
                    result["contains_homoglyphs"] = 1
                    break
            result["punycode_severity"] = 50 if result["contains_homoglyphs"] else 30
    except Exception:
        pass
    return result

def load_valid_tlds():
    try:
        resp = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", timeout=5)
        return {line.strip().lower() for line in resp.text.splitlines() if line and not line.startswith("#")}
    except Exception:
        return {"com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "xyz", "ai", "in", "us", "uk", "de"}

VALID_TLDS = load_valid_tlds()

def check_uncommon_port(parsed) -> bool:
    return parsed.port not in (80, 443) if parsed and parsed.port else False

def is_valid_url(u: str) -> bool:
    u = (u or "").strip()
    if " " in u or not u:
        return False
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    try:
        p = urlparse(u)
        if not p.hostname or "." not in p.hostname:
            return False
        ext = tldextract.extract(p.hostname)
        return bool(ext.domain and ext.suffix)
    except Exception:
        return False

# ---------------- core: extract_url_features ----------------
def extract_url_features(u: str) -> dict:
    # parse with default scheme if none
    try:
        parsed = urlparse(u if u.startswith(("http://", "https://")) else "http://" + (u or ""))
    except Exception:
        return {}

    host = (parsed.hostname or "").lower().strip()
    if not host:
        return {}

    ext = tldextract.extract(host)
    domain = (ext.domain or "").lower()
    tld = (ext.suffix or "").lower()
    full_domain = f"{domain}.{tld}" if domain and tld else ""

    # require valid tld domain (reject plain 'google')
    if not domain or not tld:
        return {"error": "invalid_domain"}

    # If the **host** is an exact whitelist match (base or www.base) → safe early return
    if is_legit_domain(host):
        features = {
            "scheme": parsed.scheme,
            "scheme_https": int(parsed.scheme == "https"),
            "contains_at": 0,
            "host_is_ip": 0,
            "hyphens": host.count("-"),
            "length": len(u),
            "is_legit": True,
            "tld": tld,
            "tld_valid": int(tld in VALID_TLDS),
            "tld_suspicious": int((tld not in VALID_TLDS) or (tld in SUSPICIOUS_TLDS)),
            "subdomain_depth": host.count("."),
            "digits_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
            "path_length": len(parsed.path or ""),
            "query_length": len(parsed.query or ""),
            "fragment_present": int(bool(parsed.fragment)),
            "port_present": int(parsed.port is not None),
            "port": parsed.port if parsed.port else None,
            "uncommon_port": int(check_uncommon_port(parsed)),
            "word_hits": [],
            "word_hits_count": 0,
            "domain_age_days": get_domain_age(domain),
            "ssl_valid": int(get_ssl_validity(domain) if parsed.scheme == "https" else 0),
            "homograph": int(detect_homograph(domain)),
            "brand_similarity": {},
            "brand_similarity_score": 0,
            "redirect_count": 0,
        }
        print("Extracted URL features (LEGIT):", features)
        return features

    # NOT legit → compute suspicious features
    word_hits = [w for w in SUSPICIOUS_WORDS if w in (u or "").lower()]
    brand_distances = brand_similarity_score(domain) if domain else {}
    brand_similarity_score_val = min(brand_distances.values()) if brand_distances else 10
    tld_valid = tld in VALID_TLDS
    tld_suspicious = int((not tld_valid) or (tld in SUSPICIOUS_TLDS))

    features = {
        "scheme": parsed.scheme,
        "scheme_https": int(parsed.scheme == "https"),
        "contains_at": int("@" in (u or "")),
        "host_is_ip": int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))),
        "hyphens": host.count("-"),
        "length": len(u or ""),
        "is_legit": False,
        "tld": tld,
        "tld_valid": int(tld_valid),
        "tld_suspicious": tld_suspicious,
        "subdomain_depth": host.count("."),
        "digits_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
        "path_length": len(parsed.path or ""),
        "query_length": len(parsed.query or ""),
        "fragment_present": int(bool(parsed.fragment)),
        "port_present": int(parsed.port is not None),
        "port": parsed.port if parsed.port else None,
        "uncommon_port": int(check_uncommon_port(parsed)),
        "word_hits": word_hits,
        "word_hits_count": len(word_hits),
        "domain_age_days": get_domain_age(domain),
        "ssl_valid": int(get_ssl_validity(domain) if parsed.scheme == "https" else 0),
        "homograph": int(detect_homograph(domain)),
        "brand_similarity": brand_distances,
        "brand_similarity_score": brand_similarity_score_val,
        "redirect_count": count_redirects(u),
    }

    print("Extracted URL features:", features)
    return features