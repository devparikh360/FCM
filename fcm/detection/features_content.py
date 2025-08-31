import os
from urllib.parse import urlparse, unquote

DANGEROUS_EXTS = {".exe",".scr",".js",".vbs",".jar",".bat",".com",".msi",".ps1",".apk"}
DOC_EXTS = {".pdf",".doc",".docx",".xls",".xlsx",".txt",".rtf",".ppt",".pptx"}
IMG_EXTS = {".png",".jpg",".jpeg",".gif",".webp",".svg"}

BAIT_WORDS = {"invoice","statement","payment","secure","confirm","verify","bank","account","unlock","urgent"}

def _guess_ext_from_url(u: str) -> str:
    try:
        p = urlparse(u)
        tail = os.path.basename(p.path or "")
        tail = unquote(tail)
        _, ext = os.path.splitext(tail.lower())
        return ext
    except Exception:
        return ""

def extract_content_features(u: str) -> dict:
    ext = _guess_ext_from_url(u)
    all_exts = DANGEROUS_EXTS | DOC_EXTS | IMG_EXTS

    is_dangerous = ext in DANGEROUS_EXTS
    is_known_doc = ext in DOC_EXTS
    is_image = ext in IMG_EXTS
    very_long_query = False
    has_bait = any(w in u.lower() for w in BAIT_WORDS)

    try:
        qlen = len(urlparse(u).query or "")
        very_long_query = qlen > 300
    except Exception:
        pass

    return {
        "ext": ext or "(none)",
        "is_dangerous": is_dangerous,
        "is_known_doc": is_known_doc,
        "is_image": is_image,
        "very_long_query": very_long_query,
        "has_bait_words": has_bait,
        "recognized_ext": (ext in all_exts),
    }
