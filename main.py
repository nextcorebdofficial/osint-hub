"""OSINT Hub: every tool from OSINT Framework in one place, plus built-in lookups.

Run:  python -m uvicorn main:app --reload
"""
import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import time
import uuid
from collections import deque
from pathlib import Path

import httpx
import markdown
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

BASE = Path(__file__).parent


def _load_dotenv() -> None:
    p = BASE / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("\"'"))


_load_dotenv()

import db  # noqa: E402  (needs env loaded first)
import extras  # noqa: E402
import lookups  # noqa: E402
import report  # noqa: E402

app = FastAPI(title="OSINT Hub")
templates = Jinja2Templates(directory=str(BASE / "templates"))

# ---------------------------------------------------------------- catalog

TREE = json.loads((BASE / "data.json").read_text(encoding="utf-8"))
TOOLS: list[dict] = []


def _flatten(node: dict, path: list[str]) -> None:
    if node.get("type") == "url":
        TOOLS.append({
            "id": len(TOOLS),
            "name": node["name"],
            "url": node.get("url", ""),
            "description": node.get("description", ""),
            "category": path[1] if len(path) > 1 else "",
            "path": " > ".join(path[1:]),
            "pricing": node.get("pricing", ""),
            "opsec": node.get("opsec", ""),
            "local": bool(node.get("localInstall")),
            "api": bool(node.get("api")),
            "dork": bool(node.get("googleDork")),
            "registration": bool(node.get("registration")),
            "deprecated": bool(node.get("deprecated")),
            "status": node.get("status", ""),
        })
        return
    for child in node.get("children", []) or []:
        _flatten(child, path + [node["name"]])


_flatten(TREE, [])
CATEGORIES = sorted({t["category"] for t in TOOLS})

TARGET_CATEGORIES = {
    "username": ["Username", "Social Networks", "Online Communities", "Dating", "Instant Messaging"],
    "email": ["Email Address", "Social Networks"],
    "domain": ["Domain Name", "Cloud Infrastructure", "Cyber Threat Intelligence", "Archives"],
    "ip": ["IP & MAC Address", "Cyber Threat Intelligence", "Geolocation Tools / Maps"],
    "phone": ["Telephone Numbers", "Instant Messaging"],
    "url": ["Domain Name", "Archives", "Malicious File Analysis", "Disinformation & Media Verification"],
    "crypto": ["Blockchain & Cryptocurrency"],
    "company": ["Business Records", "Compliance & Risk Intelligence", "Public Records"],
}

EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
DOMAIN_RE = re.compile(r"([a-z0-9-]+\.)+[a-z0-9-]{2,}")
CRYPTO_RE = re.compile(r"(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{20,60})")


def detect_type(value: str) -> str:
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if EMAIL_RE.fullmatch(v):
        return "email"
    if re.match(r"https?://", v, re.I):
        return "url"
    if re.fullmatch(r"\+?[\d\s\-()]{7,20}", v):
        return "phone"
    if CRYPTO_RE.fullmatch(v):
        return "crypto"
    if DOMAIN_RE.fullmatch(v.lower()):
        return "domain"
    return "username"


def normalize(kind: str, value: str) -> str:
    v = value.strip()
    if kind == "domain":
        v = re.sub(r"^https?://", "", v, flags=re.I).split("/")[0].lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(v):
            raise ValueError("invalid domain")
    elif kind == "ip":
        v = str(ipaddress.ip_address(v))
    elif kind == "email":
        if not EMAIL_RE.fullmatch(v):
            raise ValueError("invalid email address")
    elif kind == "url":
        if not re.match(r"https?://", v, re.I):
            raise ValueError("URL must start with http:// or https://")
    elif kind == "crypto":
        if not CRYPTO_RE.fullmatch(v):
            raise ValueError("unrecognised Bitcoin or Ethereum address")
    elif kind == "username":
        if not re.fullmatch(r"[\w.\-]{1,64}", v):
            raise ValueError("username may contain letters, digits, '.', '_' and '-' (max 64)")
    elif kind == "company":
        if not 2 <= len(v) <= 100:
            raise ValueError("company name must be 2-100 characters")
    return v


# ---------------------------------------------------------------- investigation service

UA = {"User-Agent": "OSINT-Hub/1.0 (research tool)"}
_CACHE: dict[tuple, tuple[float, dict]] = {}
CACHE_TTL = 900


def _cache_get(key: tuple):
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    return None


def _cache_put(key: tuple, val: dict) -> None:
    if len(_CACHE) > 500:
        _CACHE.pop(next(iter(_CACHE)))
    _CACHE[key] = (time.time(), val)


async def run_investigation(kind: str, value: str, opts: dict, progress: dict) -> dict:
    if kind not in TARGET_CATEGORIES:
        raise ValueError(f"unknown type {kind}")
    value = normalize(kind, value)
    limit = max(1, min(int(opts.get("limit") or 200), 700))
    region = opts.get("region") or None
    key = (kind, value, limit, region)
    data = _cache_get(key)
    cached = data is not None
    if data is None:
        async with httpx.AsyncClient(headers=UA, timeout=15) as client:
            if kind == "domain":
                data = await lookups.lookup_domain(client, value)
            elif kind == "ip":
                data = await lookups.lookup_ip(client, value)
            elif kind == "email":
                data = await lookups.lookup_email(client, value)
            elif kind == "username":
                data = await lookups.lookup_username(client, value, limit, progress)
            elif kind == "phone":
                data = lookups.lookup_phone(value, region)
            elif kind == "crypto":
                data = await lookups.lookup_crypto(client, value)
            elif kind == "url":
                data = await lookups.lookup_url(client, value)
            elif kind == "company":
                data = await lookups.lookup_company(client, value)
        _cache_put(key, data)
    cats = TARGET_CATEGORIES[kind]
    related = [t for t in TOOLS if t["category"] in cats and not t["deprecated"]]
    return {"type": kind, "value": value, "lookup": data, "cached": cached,
            "tools": related, "tool_categories": cats}


JOBS: dict[str, dict] = {}


async def _run_job(job: dict, kind: str, value: str, opts: dict) -> None:
    try:
        job["result"] = await run_investigation(kind, value, opts, job["progress"])
        job["status"] = "done"
    except Exception as e:  # surfaced to the UI as a message
        job["status"] = "error"
        job["error"] = str(e) or e.__class__.__name__


# ---------------------------------------------------------------- auth and rate limiting

SECRET = os.environ.get("APP_SECRET") or secrets.token_hex(16)
OPEN_PATHS = {"/login", "/api/health"}
_HITS: dict[tuple, deque] = {}


def _token() -> str:
    return hmac.new(SECRET.encode(), os.environ.get("APP_PASSWORD", "").encode(), hashlib.sha256).hexdigest()


def _allow(ip: str, bucket: str, limit: int) -> bool:
    now = time.time()
    q = _HITS.setdefault((ip, bucket), deque())
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    if len(_HITS) > 5000:
        for k in [k for k, v in _HITS.items() if not v or now - v[-1] > 60]:
            del _HITS[k]
    return True


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@app.middleware("http")
async def guard(request: Request, call_next):
    resp = await _gate(request, call_next)
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
        resp.headers.setdefault("Content-Security-Policy", CSP)
    return resp


async def _gate(request: Request, call_next):
    path = request.url.path
    if os.environ.get("APP_PASSWORD") and path not in OPEN_PATHS and not path.startswith("/legal/"):
        if not hmac.compare_digest(request.cookies.get("osint_session", ""), _token()):
            if path.startswith("/api"):
                return JSONResponse({"detail": "login required"}, status_code=401)
            return RedirectResponse("/login", status_code=303)
    heavy = request.method == "POST" and path in ("/api/investigate", "/api/jobs", "/api/toolbox/exif")
    limit = int(os.environ.get("RATE_LIMIT_HEAVY", "20" if heavy else "300")) if heavy else \
        int(os.environ.get("RATE_LIMIT_GENERAL", "300"))
    ip = request.client.host if request.client else "?"
    if not _allow(ip, "heavy" if heavy else "general", limit):
        return JSONResponse({"detail": "rate limit exceeded, try again in a minute"}, status_code=429)
    return await call_next(request)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": False})


@app.post("/login")
async def login(request: Request, password: str = Form("")):
    expected = os.environ.get("APP_PASSWORD", "")
    if not expected:
        return RedirectResponse("/", status_code=303)
    if hmac.compare_digest(password.encode(), expected.encode()):
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie("osint_session", _token(), httponly=True, samesite="lax", max_age=7 * 86400,
                        secure=request.url.scheme == "https")
        return resp
    return templates.TemplateResponse(request, "login.html", {"error": True}, status_code=401)


# ---------------------------------------------------------------- accountability and data minimisation

PURPOSES = {
    "own-assets": "Checking my own accounts, domains or assets",
    "authorised-security": "Security work I am authorised to do (written permission or my employer's assets)",
    "journalism-research": "Journalism, fact-checking or academic research in the public interest",
    "fraud-prevention": "Checking a suspected scam, fraud or phishing attempt",
    "education": "Learning or training on targets I own or that exist for practice",
}


def _audit(kind: str, value: str, purpose: str) -> None:
    """Append one line per investigation: time, type, purpose and a keyed hash of the target.

    The target itself and the client IP are never written, so the log shows how the tool is used
    without becoming a list of people who were looked up.
    """
    path = os.environ.get("AUDIT_LOG", str(BASE / "audit.log"))
    if not path:
        return
    digest = hmac.new(SECRET.encode(), value.lower().encode(), hashlib.sha256).hexdigest()[:16]
    line = json.dumps({"t": int(time.time()), "type": kind, "purpose": purpose, "target_hmac": digest})
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _purge_old_cases() -> None:
    try:
        days = int(os.environ.get("CASE_RETENTION_DAYS") or 0)
    except ValueError:
        days = 0
    if days > 0:
        db.purge_older_than(days)


_purge_old_cases()

LEGAL = {
    "privacy": ("Privacy Policy", "PRIVACY_POLICY.md"),
    "terms": ("Terms of Use", "TERMS_OF_USE.md"),
    "acceptable-use": ("Acceptable Use Policy", "ACCEPTABLE_USE_POLICY.md"),
    "disclaimer": ("Disclaimer", "DISCLAIMER.md"),
}


@app.get("/legal/{name}", response_class=HTMLResponse)
async def legal(request: Request, name: str):
    if name not in LEGAL:
        raise HTTPException(404, "unknown page")
    title, fname = LEGAL[name]
    text = (BASE / "docs" / "legal" / fname).read_text(encoding="utf-8")
    op = os.environ.get("OPERATOR_NAME", "").strip()
    contact = os.environ.get("OPERATOR_CONTACT", "").strip()
    law = os.environ.get("OPERATOR_JURISDICTION", "").strip()
    text = (text.replace("[OPERATOR_NAME]", op or "[OPERATOR_NAME]")
            .replace("[OPERATOR_CONTACT]", contact or "[OPERATOR_CONTACT]")
            .replace("[JURISDICTION]", law or "[JURISDICTION]"))
    return templates.TemplateResponse(request, "legal.html", {
        "title": title, "body": markdown.markdown(text, extensions=["tables"]),
        "configured": bool(op and contact and law)})


# ---------------------------------------------------------------- routes: pages and catalog

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "total": len(TOOLS), "categories": CATEGORIES})


@app.get("/api/health")
async def health():
    return {"ok": True, "tools": len(TOOLS)}


@app.get("/api/config")
async def config():
    return {"keys": lookups.configured_keys(), "auth": bool(os.environ.get("APP_PASSWORD")),
            "encode_ops": list(extras.OPS), "target_types": list(TARGET_CATEGORIES),
            "purposes": PURPOSES,
            "operator": os.environ.get("OPERATOR_NAME", "").strip(),
            "retention_days": int(os.environ.get("CASE_RETENTION_DAYS") or 0)}


@app.get("/api/categories")
async def categories():
    counts: dict[str, int] = {}
    for t in TOOLS:
        counts[t["category"]] = counts.get(t["category"], 0) + 1
    return [{"name": c, "count": counts[c]} for c in CATEGORIES]


@app.get("/api/tools")
async def tools(q: str = "", category: str = "", pricing: str = "", flag: str = "",
                limit: int = Query(60, le=2000), offset: int = 0):
    ql = q.lower().strip()
    res = [
        t for t in TOOLS
        if (not category or t["category"] == category)
        and (not pricing or t["pricing"] == pricing)
        and (flag not in ("api", "local", "dork") or t.get(flag))
        and (not ql or ql in (t["name"] + " " + t["description"] + " " + t["path"]).lower())
    ]
    return {"total": len(res), "items": res[offset:offset + limit]}


# ---------------------------------------------------------------- routes: investigations

def _parse_target(payload: dict) -> tuple[str, str]:
    value = str(payload.get("value", "")).strip()
    if not value:
        raise HTTPException(400, "value is required")
    if payload.get("purpose") not in PURPOSES:
        raise HTTPException(400, "purpose is required, one of: " + ", ".join(PURPOSES))
    return payload.get("type") or detect_type(value), value


@app.post("/api/investigate")
async def investigate(payload: dict):
    kind, value = _parse_target(payload)
    _audit(kind, value, payload["purpose"])
    try:
        return await run_investigation(kind, value, payload, {})
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/jobs")
async def start_job(payload: dict):
    kind, value = _parse_target(payload)
    if kind not in TARGET_CATEGORIES:
        raise HTTPException(400, f"unknown type {kind}")
    try:
        normalize(kind, value)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(kind, value, payload["purpose"])
    if len(JOBS) >= 200:
        JOBS.pop(next(iter(JOBS)))
    job_id = uuid.uuid4().hex
    job = {"status": "running", "progress": {}, "type": kind, "value": value}
    job["task"] = asyncio.create_task(_run_job(job, kind, value, payload))
    JOBS[job_id] = job
    return {"id": job_id}


@app.get("/api/jobs/{job_id}")
async def job_status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")
    return {k: job[k] for k in ("status", "progress", "type", "value", "result", "error") if k in job}


# ---------------------------------------------------------------- routes: cases

@app.get("/api/cases")
async def cases():
    _purge_old_cases()
    return db.list_cases()


@app.post("/api/cases")
async def new_case(payload: dict):
    name = str(payload.get("name", "")).strip()
    if not name or len(name) > 120:
        raise HTTPException(400, "name is required (max 120 characters)")
    return db.create_case(name)


@app.get("/api/cases/{case_id}")
async def case_detail(case_id: int):
    case = db.get_case(case_id)
    if not case:
        raise HTTPException(404, "case not found")
    return case


@app.delete("/api/cases/{case_id}")
async def remove_case(case_id: int):
    if not db.delete_case(case_id):
        raise HTTPException(404, "case not found")
    return {"ok": True}


@app.post("/api/cases/{case_id}/items")
async def save_item(case_id: int, payload: dict):
    result = payload.get("result")
    if not isinstance(result, dict) or not payload.get("value") or not payload.get("kind"):
        raise HTTPException(400, "kind, value and result are required")
    item = db.add_item(case_id, str(payload["kind"]), str(payload["value"]), result, str(payload.get("note", "")))
    if not item:
        raise HTTPException(404, "case not found")
    return item


@app.patch("/api/items/{item_id}")
async def edit_item(item_id: int, payload: dict):
    if not db.update_note(item_id, str(payload.get("note", ""))[:2000]):
        raise HTTPException(404, "item not found")
    return {"ok": True}


@app.delete("/api/items/{item_id}")
async def remove_item(item_id: int):
    if not db.delete_item(item_id):
        raise HTTPException(404, "item not found")
    return {"ok": True}


@app.get("/api/cases/{case_id}/export")
async def export_case(case_id: int, format: str = "md"):
    case = db.get_case(case_id)
    if not case:
        raise HTTPException(404, "case not found")
    if format == "json":
        return Response(json.dumps(case, indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="case-{case_id}.json"'})
    if format == "html":
        return HTMLResponse(report.to_html(case))
    if format == "md":
        return Response(report.to_markdown(case), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="case-{case_id}.md"'})
    raise HTTPException(400, "format must be md, json or html")


# ---------------------------------------------------------------- routes: toolbox

@app.post("/api/toolbox/encode")
async def toolbox_encode(payload: dict):
    try:
        return {"result": extras.run_op(str(payload.get("op", "")), str(payload.get("text", "")))}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/toolbox/dorks")
async def toolbox_dorks(payload: dict):
    # POST, not GET: the target is personal data and must not end up in URLs or access logs.
    target = str(payload.get("target", "")).strip()
    if not target or len(target) > 200:
        raise HTTPException(400, "target is required (max 200 characters)")
    kind = payload.get("type") or detect_type(target)
    return {"type": kind, "dorks": extras.dorks(kind, target)}


@app.post("/api/toolbox/exif")
async def toolbox_exif(file: UploadFile = File(...)):
    data = await file.read(15_000_001)
    if len(data) > 15_000_000:
        raise HTTPException(413, "file too large (max 15 MB)")
    try:
        return extras.read_exif(data)
    except Exception:
        raise HTTPException(400, "not a readable image file")
