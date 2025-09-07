import os
import re

# Dangerous / suspicious extensions
DANGEROUS_EXTENSIONS = {"exe", "bat", "cmd", "sh", "js", "vbs", "scr", "jar", "ps1", "apk", "com"}
SAFE_DOCS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf"}
SAFE_IMAGES = {"jpg", "jpeg", "png", "gif", "bmp", "svg", "webp"}

# Bait words
BAIT_WORDS = [
    "invoice", "payment", "ticket", "statement", "lottery",
    "win", "prize", "bonus", "gift", "refund", "urgent",
    "secure", "confirm", "verify", "unlock"
]

def extract_content_features(u: str) -> dict:
    low_u = u.lower()
    ext = os.path.splitext(u.split("?")[0])[1].lower().strip(".")

    filename = os.path.basename(u.split("?")[0])
    query = u.split("?")[-1] if "?" in u else ""

    features = {
        "ext": ext,
        "is_dangerous": ext in DANGEROUS_EXTENSIONS,
        "is_known_doc": ext in SAFE_DOCS,
        "is_image": ext in SAFE_IMAGES,
        "recognized_ext": bool(ext),
        "has_bait_words": any(w in low_u for w in BAIT_WORDS),
        "very_long_query": len(query) > 150,
        "filename_length": len(filename),
        "contains_double_ext": bool(ext and "." in filename.replace(f".{ext}", "")),
        "digits_in_filename_ratio": sum(c.isdigit() for c in filename) / max(len(filename), 1),
        "special_chars_in_filename": len(re.findall(r"[!@#$%^&*()_+=~`]", filename)),
        "suspicious_patterns": bool(re.search(r"(?:\d{3,}-\d{2,}-\d{2,})|(?:password)|(?:login)", low_u))
    }
    return features
