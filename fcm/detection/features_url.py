import re
import ssl
import socket
import requests
import idna
import tldextract
from datetime import datetime
from urllib.parse import urlparse
from Levenshtein import distance as levenshtein


SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz"}
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "win", "password","update","bank","account",
    "secure","confirm","banking","webscr","paypal","free","bonus","gift",
    "prize","lottery","credit"
]
BRAND_KEYWORDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook"]

# features_url.py (at top)
with open("data/leg.txt", "r", encoding="utf-8") as f:
    LEGIT_DOMAINS = set(line.strip().lower() for line in f if line.strip())

def is_legit_domain(domain: str) -> bool:
    return domain.lower() in LEGIT_DOMAINS


def get_domain_age(domain: str) -> int:
    # fail-safe stub
    return -1

def get_ssl_validity(domain: str) -> bool:
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
    try:
        ascii_version = idna.encode(domain).decode()
        return domain != ascii_version
    except Exception:
        return False

def brand_similarity_score(domain: str) -> int:
    """Return minimum distance to any known brand or 10 if none"""
    return {brand: levenshtein(domain, brand) for brand in BRAND_KEYWORDS}

# --- Helpers ---
def count_redirects(url: str) -> int:
    try:
        r = requests.get(url, timeout=3, allow_redirects=True)
        return len(r.history)
    except Exception:
        return 0

def check_punycode(host: str) -> dict:
    result = {
        "is_punycode": 0,
        "decoded_host": host,
        "contains_homoglyphs": 0,
        "punycode_severity": 0
    }

    try:
        if "xn--" in host:
            result["is_punycode"] = 1
            decoded = idna.decode(host)
            result["decoded_host"] = decoded

            homoglyph_map = {
                "а": "a", "е": "e", "о": "o", "і": "i", "ѕ": "s", "р": "p",
                "Ɩ": "l", "ʘ": "o", "ꞵ": "b"
            }
            for ch in decoded:
                if ch in homoglyph_map:
                    result["contains_homoglyphs"] = 1
                    break

            result["punycode_severity"] = 50 if result["contains_homoglyphs"] else 30
    except Exception:
        pass
    
    return result

# --- Load valid TLD list (from IANA root zone) ---
def load_valid_tlds():
    try:
        resp = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", timeout=5)
        valid_tlds = {line.strip().lower() for line in resp.text.splitlines() if line and not line.startswith("#")}
        return valid_tlds
    except Exception:
        # Fallback if offline: minimal list
        return {"com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "xyz", "ai", "in", "us", "uk", "de"}

VALID_TLDS = load_valid_tlds()
#------------ports-----------
def check_uncommon_port(parsed) -> bool:
    if parsed.port is None:
        return False
    return parsed.port not in [80, 443]
#----------------------
def is_valid_url(u: str) -> bool:
    try:
        parsed = urlparse(u)
        # require scheme and netloc (domain)
        if not parsed.scheme or not parsed.netloc:
            return False
        # also require at least 1 dot in hostname (to avoid "sex" / "xxx")
        if "." not in parsed.hostname:
            return False
        return True
    except Exception:
        return False

#------------------

def extract_url_features(u: str) -> dict:
    try:
        parsed = urlparse(u)
    except Exception:
        return {}

    host = parsed.hostname or ""
    ext = tldextract.extract(u)
    domain = ext.domain
    tld = ext.suffix.lower()
    path = parsed.path or ""

    # Whitelist check
    is_legit = is_legit_domain(domain)

    word_hits = [w for w in SUSPICIOUS_WORDS if w in u.lower()]
    brand_distances = brand_similarity_score(domain)

    # --- NEW: Check if TLD is valid ---
    tld_valid = tld in VALID_TLDS
    tld_suspicious = int((not tld_valid) or (tld in SUSPICIOUS_TLDS))

    features = {
        "scheme": parsed.scheme,
        "scheme_https": int(parsed.scheme == "https"),
        "contains_at": int("@" in u),
        "host_is_ip": int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))),

        "hyphens": host.count("-"),
        "length": len(u),
        "is_legit": is_legit,               # keep legit flag
        "tld": tld,
        "tld_valid": int(tld_valid),
        "tld_suspicious": tld_suspicious,
        "subdomain_depth": host.count("."),
        "digits_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
        "path_length": len(path),
        "query_length": len(parsed.query),
        "fragment_present": int(bool(parsed.fragment)),
        "port_present": int(parsed.port is not None),
        "port_present": int(parsed.port is not None),
        "port": parsed.port if parsed.port else None,
        "uncommon_port": int(check_uncommon_port(parsed)),

        "word_hits": word_hits,
        "word_hits_count": len(word_hits),

        # Advanced
        "domain_age_days": get_domain_age(host),
        "ssl_valid": int(get_ssl_validity(host) if parsed.scheme == "https" else 0),
        "homograph": int(detect_homograph(host)),
        "brand_similarity": brand_distances,
        "brand_similarity_score": min(brand_distances.values()) if brand_distances else 10,
        "redirect_count": count_redirects(u),
    }

    print("Extracted URL features:", features)
    return features


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
