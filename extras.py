"""Toolbox: encoding/decoding, hash identification, Google dork generator, EXIF reader."""
import base64
import binascii
import codecs
import hashlib
import html
import io
import re
from urllib.parse import quote, unquote

from PIL import ExifTags, Image


def _hashid(text: str) -> str:
    t = text.strip()
    if t.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt"
    if t.startswith("$6$"):
        return "sha512crypt"
    if t.startswith("$1$"):
        return "md5crypt"
    if not re.fullmatch(r"[0-9a-fA-F]+", t):
        return "unknown (not a plain hex digest)"
    return {
        32: "MD5 or NTLM", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256 (or SHA3-256)",
        96: "SHA-384", 128: "SHA-512",
    }.get(len(t), f"unknown ({len(t)} hex chars)")


OPS = {
    "base64-encode": lambda s: base64.b64encode(s.encode()).decode(),
    "base64-decode": lambda s: base64.b64decode(s + "=" * (-len(s) % 4), validate=False).decode("utf-8", "replace"),
    "hex-encode": lambda s: s.encode().hex(),
    "hex-decode": lambda s: bytes.fromhex(re.sub(r"\s|0x", "", s)).decode("utf-8", "replace"),
    "url-encode": lambda s: quote(s, safe=""),
    "url-decode": unquote,
    "html-encode": html.escape,
    "html-decode": html.unescape,
    "binary-encode": lambda s: " ".join(f"{b:08b}" for b in s.encode()),
    "binary-decode": lambda s: bytes(int(x, 2) for x in s.split()).decode("utf-8", "replace"),
    "rot13": lambda s: codecs.encode(s, "rot13"),
    "md5": lambda s: hashlib.md5(s.encode()).hexdigest(),
    "sha1": lambda s: hashlib.sha1(s.encode()).hexdigest(),
    "sha256": lambda s: hashlib.sha256(s.encode()).hexdigest(),
    "sha512": lambda s: hashlib.sha512(s.encode()).hexdigest(),
    "identify-hash": _hashid,
}


def run_op(op: str, text: str) -> str:
    if op not in OPS:
        raise ValueError(f"unknown operation, choose one of: {', '.join(OPS)}")
    if len(text) > 200_000:
        raise ValueError("input too large")
    try:
        return OPS[op](text)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"cannot {op}: {e}")


DORKS = {
    "domain": [
        ("All indexed pages", "site:{t}"),
        ("Documents", "site:{t} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx)"),
        ("Admin / login pages", "site:{t} (inurl:admin OR inurl:login OR inurl:dashboard)"),
        ("Open directory listings", 'site:{t} intitle:"index of"'),
        ("Config / log files", "site:{t} (ext:env OR ext:log OR ext:conf OR ext:cfg)"),
        ("Mentions elsewhere", '"{t}" -site:{t}'),
        ("On Pastebin", 'site:pastebin.com "{t}"'),
        ("On GitHub", 'site:github.com "{t}"'),
        ("Subdomains", "site:*.{t} -site:www.{t}"),
    ],
    "email": [
        ("Exact match", '"{t}"'),
        ("On Pastebin", 'site:pastebin.com "{t}"'),
        ("On GitHub", 'site:github.com "{t}"'),
        ("In documents", '"{t}" (filetype:pdf OR filetype:doc OR filetype:xls)'),
    ],
    "username": [
        ("Exact match", '"{t}"'),
        ("In URLs", "inurl:{t}"),
        ("On GitHub", 'site:github.com "{t}"'),
        ("On Reddit", 'site:reddit.com "{t}"'),
        ("On Pastebin", 'site:pastebin.com "{t}"'),
    ],
    "phone": [("Exact match", '"{t}"'), ("In documents", '"{t}" (filetype:pdf OR filetype:doc)')],
    "company": [
        ("Exact match", '"{t}"'),
        ("Filings and registries", '"{t}" (inurl:filing OR inurl:registry OR "registered office")'),
        ("Documents", '"{t}" (filetype:pdf OR filetype:xls)'),
        ("News", '"{t}" (site:reuters.com OR site:bbc.com OR site:apnews.com)'),
    ],
}


def dorks(kind: str, target: str) -> list[dict]:
    out = []
    for label, tpl in DORKS.get(kind, []):
        q = tpl.replace("{t}", target)
        qq = quote(q)
        out.append({
            "label": label, "query": q,
            "google": f"https://www.google.com/search?q={qq}",
            "duckduckgo": f"https://duckduckgo.com/?q={qq}",
            "bing": f"https://www.bing.com/search?q={qq}",
        })
    return out


def _clean(v):
    if isinstance(v, bytes):
        return v[:64].hex()
    if isinstance(v, (list, tuple)):
        return [_clean(x) for x in v]
    if isinstance(v, (int, float, str, bool)) or v is None:
        return v
    try:
        return float(v)
    except (TypeError, ValueError):
        return str(v)


def _deg(vals, ref) -> float:
    d, m, s = (float(x) for x in vals)
    r = d + m / 60 + s / 3600
    return -r if ref in ("S", "W") else r


def read_exif(data: bytes) -> dict:
    img = Image.open(io.BytesIO(data))
    exif = img.getexif()
    tags = {ExifTags.TAGS.get(k, str(k)): _clean(v) for k, v in exif.items()}
    for k, v in exif.get_ifd(0x8769).items():
        tags[ExifTags.TAGS.get(k, str(k))] = _clean(v)
    out = {"format": img.format, "size": list(img.size), "has_exif": bool(tags), "tags": tags}
    gps = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in exif.get_ifd(0x8825).items()}
    try:
        lat = _deg(gps["GPSLatitude"], gps.get("GPSLatitudeRef"))
        lon = _deg(gps["GPSLongitude"], gps.get("GPSLongitudeRef"))
        out["gps"] = {
            "latitude": lat, "longitude": lon,
            "map": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}",
        }
    except (KeyError, TypeError, ValueError):
        pass
    return out
