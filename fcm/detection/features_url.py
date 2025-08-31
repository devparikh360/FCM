import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"zip","kim","top","gq","work","quest","country","xyz","click","rest","cf"}
SUSPICIOUS_WORDS = {"login","verify","update","secure","account","bank","pay","wallet","bonus","gift","refund","unlock"}
IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def extract_url_features(u: str) -> dict:
    try:
        p = urlparse(u)
    except Exception:
        p = urlparse("")

    host = (p.hostname or "").lower()
    path = (p.path or "") + ("?" + p.query if p.query else "")
    scheme = (p.scheme or "").lower()
    full = u or ""

    # basic parts
    length = len(full)
    hyphens = host.count("-")
    subdomain_depth = host.count(".")
    digits_ratio = sum(c.isdigit() for c in full) / max(1, len(full))
    contains_at = "@" in full
    is_punycode = host.startswith("xn--")
    tld = host.split(".")[-1] if "." in host else ""
    host_is_ip = bool(IP_HOST_RE.match(host))

    # keywords in path/query
    word_hits = [w for w in SUSPICIOUS_WORDS if w in path.lower()]
    tld_suspicious = tld in SUSPICIOUS_TLDS

    return {
        "scheme": scheme,
        "length": length,
        "hyphens": hyphens,
        "subdomain_depth": subdomain_depth,
        "digits_ratio": round(digits_ratio, 3),
        "contains_at": contains_at,
        "is_punycode": is_punycode,
        "tld": tld,
        "tld_suspicious": tld_suspicious,
        "host_is_ip": host_is_ip,
        "word_hits": word_hits,
        "host": host,
        "path": path,
    }
