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
from urllib.parse import urlparse

import httpx
import markdown
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
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

for _k in ("AUTH_MODE", "APP_SECRET", "APP_PASSWORD", "PUBLIC_URL", "REGISTRATION", "DAILY_INVESTIGATIONS",
           "TURSO_DATABASE_URL", "TURSO_AUTH_TOKEN", "MAIL_PROVIDER", "MAIL_FROM", "MAIL_API_KEY", "SMTP_HOST",
           "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "OPERATOR_NAME", "OPERATOR_CONTACT", "OPERATOR_JURISDICTION",
           "CASE_RETENTION_DAYS", "BRAND_NAME", "ALLOWED_EMAILS", "ALLOWED_EMAIL_DOMAINS", "CASES_ENABLED"):
    if os.environ.get(_k):
        os.environ[_k] = os.environ[_k].replace("\ufeff", "").strip().strip("\"'")
del _k

BRAND = os.environ.get("BRAND_NAME", "").strip() or "NextCore BD"


def auth_mode() -> str:
    """'accounts' (email + password, set AUTH_MODE=accounts), 'password' (one shared APP_PASSWORD) or 'none'."""
    if os.environ.get("AUTH_MODE", "").strip().lower() == "accounts":
        return "accounts"
    return "password" if os.environ.get("APP_PASSWORD") else "none"


def cases_enabled() -> bool:
    """Cases have no per-user separation, so a public instance without a login must not store them.

    CASES_ENABLED=1/0 decides explicitly; otherwise they are off on serverless hosts without APP_PASSWORD.
    """
    v = os.environ.get("CASES_ENABLED", "").strip().lower()
    if v:
        return v not in ("0", "false", "no", "off")
    return not (serverless() and auth_mode() == "none")


def serverless() -> bool:
    """True on Vercel (or when SERVERLESS=1): no background tasks, no shared memory, read-only disk."""
    return bool(os.environ.get("VERCEL") or os.environ.get("SERVERLESS"))


import auth  # noqa: E402  (needs env loaded first)
import db  # noqa: E402
import extras  # noqa: E402
import mailer  # noqa: E402
import lookups  # noqa: E402
import report  # noqa: E402

# The interactive API docs list every endpoint; keep them for self-hosters, hide them on account instances.
_docs = {} if auth_mode() != "accounts" else {"docs_url": None, "redoc_url": None, "openapi_url": None}
app = FastAPI(title="OSINT Hub", **_docs)
templates = Jinja2Templates(directory=str(BASE / "templates"))
def operator_name() -> str:
    """Who runs this instance. Defaults to the brand so the legal pages are never anonymous."""
    return os.environ.get("OPERATOR_NAME", "").strip() or BRAND


REPO_URL = os.environ.get("REPO_URL", "https://github.com/nextcorebdofficial/osint-hub")


def page(request: Request, name: str, ctx: dict | None = None, status: int = 200):
    """Render a template with the per-request CSP nonce every inline script and style tag needs."""
    return templates.TemplateResponse(
        request, name, {"nonce": getattr(request.state, "nonce", ""), "brand": BRAND, **(ctx or {})},
        status_code=status)


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
        job["error"] = (str(e) or e.__class__.__name__)[:200]


# ---------------------------------------------------------------- auth and rate limiting

SECRET = os.environ.get("APP_SECRET") or secrets.token_hex(16)
if serverless() and not os.environ.get("APP_SECRET"):
    # Every serverless instance would invent its own secret, so logins would fail at random.
    print("WARNING: APP_SECRET is not set; login cookies will not be valid across instances", flush=True)
_HITS: dict[tuple, deque] = {}


def _token() -> str:
    return hmac.new(SECRET.encode(), os.environ.get("APP_PASSWORD", "").encode(), hashlib.sha256).hexdigest()


def _client_ip(request: Request) -> str:
    # Behind Vercel's proxy the socket peer is the proxy; the platform sets X-Forwarded-For itself.
    # Only trusted on Vercel; elsewhere use --proxy-headers with --forwarded-allow-ips.
    if os.environ.get("VERCEL"):
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "?"


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
    "Referrer-Policy": "same-origin",  # no-referrer would make browsers send "Origin: null" on form posts
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
}


def _csp(nonce: str) -> str:
    # Scripts and style blocks need the per-request nonce; only style="" attributes stay unrestricted.
    return (f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; "
            "style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; "
            "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


MAX_JSON_BODY = 1_000_000


def max_upload() -> int:
    return 4_000_000 if serverless() else 15_000_000  # Vercel rejects bodies above ~4.5 MB anyway


@app.middleware("http")
async def guard(request: Request, call_next):
    request.state.nonce = secrets.token_urlsafe(16)
    request.state.user = None
    resp = await _gate(request, call_next)
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
        resp.headers.setdefault("Content-Security-Policy", _csp(request.state.nonce))
    if request.url.scheme == "https" or serverless():
        resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return resp


OPEN_PATHS = {"/login", "/api/health", "/robots.txt", "/.well-known/security.txt"}
ACCOUNT_PUBLIC = {"/", "/register", "/verify", "/resend", "/forgot", "/reset"}
AUTH_POSTS = ("/login", "/register", "/resend", "/forgot", "/reset")


def _same_origin(request: Request) -> bool:
    # Browsers say where a request came from. Sec-Fetch-Site is the most reliable signal and cannot be
    # forged by a web page; fall back to the Origin header for older browsers.
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        return site in ("same-origin", "none")
    origin = request.headers.get("origin")
    if origin is None:  # not a browser (curl, tests)
        return True
    host = (request.headers.get("x-forwarded-host") if serverless() else None) or request.headers.get("host", "")
    return origin != "null" and urlparse(origin).netloc == host


_USERS: dict[int, tuple[float, dict | None]] = {}


def _user_cached(uid: int) -> dict | None:
    hit = _USERS.get(uid)
    if hit and time.time() - hit[0] < 60:
        return hit[1]
    try:
        user = db.get_user(uid)
    except Exception:
        return None  # database unreachable: treat as signed out rather than failing open
    if len(_USERS) > 1000:
        _USERS.clear()
    _USERS[uid] = (time.time(), user)
    return user


def _session_user(request: Request) -> dict | None:
    tok = request.cookies.get("osint_session", "")
    uid = auth.session_uid(tok)
    if uid is None:
        return None
    user = _user_cached(uid)
    return user if user and auth.session_valid(SECRET, tok, user) else None


def _uid(request: Request) -> int | None:
    u = getattr(request.state, "user", None)
    return u["id"] if u else None


async def _gate(request: Request, call_next):
    path, method, mode = request.url.path, request.method, auth_mode()
    cl = request.headers.get("content-length", "")
    if cl.isdigit() and int(cl) > (max_upload() + 100_000 if path == "/api/toolbox/exif" else MAX_JSON_BODY):
        return JSONResponse({"detail": "request body too large"}, status_code=413)
    if method in ("POST", "PUT", "PATCH", "DELETE") and not _same_origin(request):
        return JSONResponse({"detail": "cross-site request blocked"}, status_code=403)

    public = path in OPEN_PATHS or path.startswith("/legal/") or (mode == "accounts" and path in ACCOUNT_PUBLIC)
    if mode == "accounts":
        request.state.user = _session_user(request) if request.cookies.get("osint_session") else None
    if mode != "none" and not public:
        ok = (hmac.compare_digest(request.cookies.get("osint_session", ""), _token()) if mode == "password"
              else request.state.user is not None)
        if not ok:
            if path.startswith("/api"):
                return JSONResponse({"detail": "login required"}, status_code=401)
            return RedirectResponse("/login", status_code=303)
    if path.startswith(("/api/cases", "/api/items")) and not cases_enabled():
        return JSONResponse({"detail": "saved cases are turned off on this instance"}, status_code=403)

    login_post = method == "POST" and path in AUTH_POSTS
    heavy = method == "POST" and path in ("/api/investigate", "/api/jobs", "/api/toolbox/exif")
    if login_post:
        bucket, limit = "auth", int(os.environ.get("RATE_LIMIT_AUTH", "10"))
    elif heavy:
        bucket, limit = "heavy", int(os.environ.get("RATE_LIMIT_HEAVY", "20"))
    else:
        bucket, limit = "general", int(os.environ.get("RATE_LIMIT_GENERAL", "300"))
    who = f"u{request.state.user['id']}" if request.state.user and not login_post else _client_ip(request)
    if not _allow(who, bucket, limit):
        return JSONResponse({"detail": "rate limit exceeded, try again in a minute"}, status_code=429)
    return await call_next(request)


def _set_session(resp, request: Request, value: str) -> None:
    resp.set_cookie("osint_session", value, httponly=True, samesite="lax", max_age=7 * 86400,
                    secure=request.url.scheme == "https"
                    or (serverless() and request.headers.get("x-forwarded-proto") == "https"))


# ---------------------------------------------------------------- sign in, accounts

_FAILS: dict[str, list[float]] = {}  # email -> recent failed attempts (per instance, best effort)
LOCK_AFTER, LOCK_WINDOW = 5, 900


def _locked(email: str) -> bool:
    now = time.time()
    recent = [x for x in _FAILS.get(email, []) if now - x < LOCK_WINDOW]
    _FAILS[email] = recent
    if len(_FAILS) > 5000:
        _FAILS.clear()
    return len(recent) >= LOCK_AFTER


def registration_mode() -> str:
    v = os.environ.get("REGISTRATION", "open").strip().lower()
    return v if v in ("open", "invite", "closed") else "open"


def _csv(name: str) -> set[str]:
    return {x.strip().lower() for x in os.environ.get(name, "").split(",") if x.strip()}


def may_register(email: str) -> bool:
    mode = registration_mode()
    if mode == "closed":
        return False
    if mode == "invite":
        return email in _csv("ALLOWED_EMAILS") or email.split("@")[1] in _csv("ALLOWED_EMAIL_DOMAINS")
    return True


def accounts_problem() -> str:
    """Why accounts cannot work on this deployment yet, or an empty string."""
    if serverless() and not os.environ.get("APP_SECRET"):
        return "APP_SECRET is not set"
    if db.backend() == "sqlite-temp" and not os.environ.get("ALLOW_TEMP_ACCOUNTS"):
        return "no persistent database: set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN"
    if serverless() and not os.environ.get("PUBLIC_URL"):
        return "PUBLIC_URL is not set (links in emails must not depend on the Host header)"
    if not mailer.configured() and not os.environ.get("ALLOW_UNVERIFIED"):
        return "email sending is not configured: set MAIL_PROVIDER, MAIL_FROM and MAIL_API_KEY (or ALLOW_UNVERIFIED=1)"
    return ""


def public_url(request: Request) -> str:
    # Never build email links from the Host header on a public host: that allows password-reset poisoning.
    return (os.environ.get("PUBLIC_URL", "").strip().rstrip("/")) or str(request.base_url).rstrip("/")


_MAILS: dict[str, list[float]] = {}


def _mail_ok(email: str) -> bool:
    """At most 3 emails per address per hour, so nobody can use us to flood an inbox."""
    now = time.time()
    recent = [x for x in _MAILS.get(email, []) if now - x < 3600]
    if len(_MAILS) > 5000:
        _MAILS.clear()
    if len(recent) >= 3:
        _MAILS[email] = recent
        return False
    _MAILS[email] = recent + [now]
    return True


async def _send_link(request: Request, user: dict, kind: str) -> str:
    """'sent', 'throttled' or 'failed'."""
    if not _mail_ok(user["email"]):
        return "throttled"
    link = f"{public_url(request)}/{kind}?token={auth.make_link_token(SECRET, kind, user)}"
    if kind == "verify":
        subject, lead, ttl = f"Confirm your email for {BRAND}", "Confirm your email address to finish creating your account.", "48 hours"
    else:
        subject, lead, ttl = f"Reset your {BRAND} password", "Someone asked to reset the password for this account. If that was you, choose a new one.", "1 hour"
    text = (f"{lead}\n\n{link}\n\nThe link works for {ttl}. If you did not ask for this, ignore this email; "
            f"nothing changes.\n\n{BRAND}\n")
    ok = await asyncio.to_thread(mailer.send, user["email"], subject, text)
    return "sent" if ok else "failed"


def _auth_page(request: Request, name: str, error: str = "", status: int = 200):
    problem = auth_mode() == "accounts" and accounts_problem()
    if problem:
        print("ACCOUNTS UNAVAILABLE: " + problem, flush=True)
    return page(request, name, {
        "error": error, "mode": auth_mode(), "unavailable": bool(problem),
        "registration": registration_mode(), "operator": operator_name()}, status)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if auth_mode() == "accounts" and _session_user(request):
        return RedirectResponse("/app", status_code=303)
    return _auth_page(request, "login.html")


@app.post("/login")
async def login(request: Request, password: str = Form(""), email: str = Form("")):
    mode = auth_mode()
    if mode == "none":
        return RedirectResponse("/", status_code=303)
    if mode == "password":
        expected = os.environ.get("APP_PASSWORD", "")
        if hmac.compare_digest(password.encode(), expected.encode()):
            resp = RedirectResponse("/", status_code=303)
            _set_session(resp, request, _token())
            return resp
        return _auth_page(request, "login.html", "Wrong password.", 401)
    if accounts_problem():
        return _auth_page(request, "login.html", "", 503)
    try:
        email = auth.clean_email(email)
    except ValueError:
        email = ""
    if email and _locked(email):
        return _auth_page(request, "login.html", "Too many attempts. Try again in 15 minutes.", 429)
    user = db.get_user_by_email(email) if email else None
    # Always run the hash so a wrong email takes as long as a wrong password.
    ok = auth.verify_password(password[:auth.MAX_PASSWORD], user["pw"] if user else auth.DUMMY_HASH)
    if not (user and ok):
        if email:
            _FAILS.setdefault(email, []).append(time.time())
        return _auth_page(request, "login.html", "Wrong email or password.", 401)
    _FAILS.pop(email, None)
    if mailer.configured() and not user.get("verified"):
        return page(request, "message.html", {
            "title": "Confirm your email first",
            "message": "Your account is not active yet. Open the link we emailed you, or ask for a new one below.",
            "link": ("/login", "Back to sign in"), "resend_email": email}, 403)
    resp = RedirectResponse("/app", status_code=303)
    _set_session(resp, request, auth.make_session(SECRET, user))
    return resp


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    if auth_mode() != "accounts":
        raise HTTPException(404, "not found")
    return _auth_page(request, "register.html")


@app.post("/register")
async def register(request: Request, email: str = Form(""), password: str = Form(""),
                   password2: str = Form(""), terms: str = Form("")):
    if auth_mode() != "accounts":
        raise HTTPException(404, "not found")
    if accounts_problem():
        return _auth_page(request, "register.html", "", 503)
    try:
        email = auth.clean_email(email)
        if not may_register(email):
            raise ValueError("Registration is not open for this email address on this instance.")
        if password != password2:
            raise ValueError("The two passwords do not match.")
        auth.check_password(password, email)
        if terms != "on":
            raise ValueError("You must accept the terms and the acceptable use policy.")
    except ValueError as e:
        return _auth_page(request, "register.html", str(e), 400)
    uid = db.create_user(email, auth.hash_password(password), time.time())
    if uid is None:
        return _auth_page(request, "register.html", "This email is already registered. Sign in instead.", 409)
    user = db.get_user(uid)
    if mailer.configured():
        outcome = await _send_link(request, user, "verify")
        if outcome != "sent":
            return page(request, "message.html", {
                "title": "Account created, email not sent",
                "message": "Your account exists, but we could not send the confirmation email just now. "
                           "Wait a minute and ask for a new link below.",
                "link": ("/login", "Back to sign in"), "resend_email": user["email"]}, 202)
        return _auth_page_msg(request, "Check your email",
                              "We sent a confirmation link to your address. Open it to activate your account. "
                              "It can take a minute; look in the spam folder too.")
    db.set_verified(uid)  # self-hosted without email (ALLOW_UNVERIFIED)
    resp = RedirectResponse("/app", status_code=303)
    _set_session(resp, request, auth.make_session(SECRET, db.get_user(uid)))
    return resp


def _auth_page_msg(request: Request, title: str, message: str, status: int = 200, link=("/login", "Sign in")):
    return page(request, "message.html", {"title": title, "message": message, "link": link}, status)


@app.get("/verify", response_class=HTMLResponse)
async def verify(request: Request, token: str = ""):
    uid = auth.link_token_uid(token)
    user = db.get_user(uid) if uid else None
    if not user or not auth.link_token_valid(SECRET, "verify", token, user):
        return _auth_page_msg(request, "Link not valid",
                              "This confirmation link is invalid or has expired. Sign in to get a new one.", 400)
    db.set_verified(user["id"])
    _USERS.pop(user["id"], None)
    resp = RedirectResponse("/app", status_code=303)
    _set_session(resp, request, auth.make_session(SECRET, user))
    return resp


@app.post("/resend")
async def resend(request: Request, email: str = Form("")):
    if auth_mode() != "accounts":
        raise HTTPException(404, "not found")
    try:
        user = db.get_user_by_email(auth.clean_email(email))
    except ValueError:
        user = None
    if user and not user.get("verified") and mailer.configured():
        await _send_link(request, user, "verify")
    return _auth_page_msg(request, "Check your email",
                          "If that address has an account waiting for confirmation, we sent a new link.")


@app.get("/forgot", response_class=HTMLResponse)
async def forgot_page(request: Request):
    if auth_mode() != "accounts":
        raise HTTPException(404, "not found")
    return page(request, "forgot.html", {})


@app.post("/forgot")
async def forgot(request: Request, email: str = Form("")):
    if auth_mode() != "accounts":
        raise HTTPException(404, "not found")
    try:
        user = db.get_user_by_email(auth.clean_email(email))
    except ValueError:
        user = None
    if user and mailer.configured():
        await _send_link(request, user, "reset")
    # Same answer whether or not the address exists, so this cannot be used to find accounts.
    return _auth_page_msg(request, "Check your email",
                          "If that address has an account, we sent a link to choose a new password. It works for 1 hour.")


def _reset_user(token: str) -> dict | None:
    uid = auth.link_token_uid(token)
    user = db.get_user(uid) if uid else None
    return user if user and auth.link_token_valid(SECRET, "reset", token, user) else None


@app.get("/reset", response_class=HTMLResponse)
async def reset_page(request: Request, token: str = ""):
    if auth_mode() != "accounts":
        raise HTTPException(404, "not found")
    if not _reset_user(token):
        return _auth_page_msg(request, "Link not valid", "This reset link is invalid, already used or has expired.",
                              400, ("/forgot", "Ask for a new link"))
    return page(request, "reset.html", {"token": token, "error": ""})


@app.post("/reset")
async def reset(request: Request, token: str = Form(""), password: str = Form(""), password2: str = Form("")):
    if auth_mode() != "accounts":
        raise HTTPException(404, "not found")
    user = _reset_user(token)
    if not user:
        return _auth_page_msg(request, "Link not valid", "This reset link is invalid, already used or has expired.",
                              400, ("/forgot", "Ask for a new link"))
    try:
        if password != password2:
            raise ValueError("The two passwords do not match.")
        auth.check_password(password, user["email"])
    except ValueError as e:
        return page(request, "reset.html", {"token": token, "error": str(e)}, 400)
    db.set_password(user["id"], auth.hash_password(password))
    db.set_verified(user["id"])  # they proved they own the address
    _USERS.pop(user["id"], None)
    _FAILS.pop(user["email"], None)
    return _auth_page_msg(request, "Password changed", "You can now sign in with your new password. "
                          "Any older sessions were signed out.")


@app.post("/logout")
async def logout():
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie("osint_session")
    return resp


@app.get("/api/account/export")
async def account_export(request: Request):
    if not request.state.user:
        raise HTTPException(404, "no account")
    return Response(json.dumps(db.export_user(request.state.user["id"]), indent=2), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="osint-hub-my-data.json"'})


@app.delete("/api/account")
async def account_delete(request: Request, payload: dict):
    user = request.state.user
    if not user:
        raise HTTPException(404, "no account")
    if not auth.verify_password(str(payload.get("password", ""))[:auth.MAX_PASSWORD], user["pw"]):
        raise HTTPException(403, "wrong password")
    db.delete_user(user["id"])
    _USERS.pop(user["id"], None)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("osint_session")
    return resp


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return "User-agent: *\nAllow: /$\nAllow: /legal/\nDisallow: /app\nDisallow: /api/\nDisallow: /login\nDisallow: /register\n"


@app.get("/.well-known/security.txt", response_class=PlainTextResponse)
async def security_txt():
    contact = os.environ.get("OPERATOR_CONTACT", "").strip()
    if not contact:
        raise HTTPException(404, "not configured")
    target = contact if contact.startswith(("http://", "https://", "mailto:")) else "mailto:" + contact
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 365 * 86400))
    return f"Contact: {target}\nExpires: {expires}\nPreferred-Languages: en, bn\n"


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
        # Read-only disk (serverless): the platform runtime logs keep the line instead.
        print("AUDIT " + line, flush=True)


_LAST_PURGE = 0.0


def _purge_old_cases() -> None:
    """At most once every 10 minutes per instance, and never at import time (cold starts stay fast)."""
    global _LAST_PURGE
    if time.time() - _LAST_PURGE < 600:
        return
    _LAST_PURGE = time.time()
    try:
        days = int(os.environ.get("CASE_RETENTION_DAYS") or 0)
    except ValueError:
        days = 0
    if days > 0:
        try:
            db.purge_older_than(days)
        except Exception as e:  # a database hiccup must not break the request that triggered the purge
            print(f"PURGE FAILED {e.__class__.__name__}", flush=True)

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
    op = operator_name()
    contact = os.environ.get("OPERATOR_CONTACT", "").strip()
    law = os.environ.get("OPERATOR_JURISDICTION", "").strip()
    text = (text.replace("[OPERATOR_NAME]", op or "[OPERATOR_NAME]")
            .replace("[OPERATOR_CONTACT]", contact or "[OPERATOR_CONTACT]")
            .replace("[JURISDICTION]", law or "[JURISDICTION]"))
    return page(request, "legal.html", {
        "title": title, "body": markdown.markdown(text, extensions=["tables"]),
        "configured": bool(op and contact and law)})


# ---------------------------------------------------------------- routes: pages and catalog

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if auth_mode() == "accounts":
        return page(request, "landing.html", {
            "total": len(TOOLS), "categories": len(CATEGORIES), "types": len(TARGET_CATEGORIES),
            "registration": registration_mode(), "operator": operator_name(),
            "repo": REPO_URL, "signed_in": request.state.user is not None,
            "retention": int(os.environ.get("CASE_RETENTION_DAYS") or 0)})
    return await app_page(request)


@app.get("/app", response_class=HTMLResponse)
async def app_page(request: Request):
    _purge_old_cases()
    return page(request, "index.html", {"total": len(TOOLS), "categories": CATEGORIES})


@app.get("/api/health")
async def health():
    return {"ok": True, "tools": len(TOOLS)}


@app.get("/api/config")
async def config(request: Request):
    user = getattr(request.state, "user", None)
    return {"keys": lookups.configured_keys(), "auth": auth_mode() != "none", "auth_mode": auth_mode(),
            "user": user["email"] if user else "",
            "encode_ops": list(extras.OPS), "target_types": list(TARGET_CATEGORIES),
            "purposes": PURPOSES, "serverless": serverless(), "storage": db.backend(),
            "cases": cases_enabled(),
            "operator": operator_name(), "daily_limit": daily_limit() if _uid_mode() else 0,
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

def _uid_mode() -> bool:
    return auth_mode() == "accounts"


def daily_limit() -> int:
    try:
        return max(0, int(os.environ.get("DAILY_INVESTIGATIONS", "100")))
    except ValueError:
        return 100


def _count_usage(request: Request) -> None:
    """Per-account daily cap, so one account cannot hammer the free sources we depend on. 0 turns it off."""
    uid, limit = _uid(request), daily_limit()
    if uid is None or not limit:
        return
    if not db.bump_usage(uid, time.strftime("%Y-%m-%d", time.gmtime()), limit):
        raise HTTPException(429, f"Daily limit reached ({limit} investigations per day). Try again tomorrow.")


def _parse_target(payload: dict) -> tuple[str, str]:
    value = str(payload.get("value", "")).strip()
    if not value:
        raise HTTPException(400, "value is required")
    if payload.get("purpose") not in PURPOSES:
        raise HTTPException(400, "purpose is required, one of: " + ", ".join(PURPOSES))
    return payload.get("type") or detect_type(value), value


@app.post("/api/investigate")
async def investigate(request: Request, payload: dict):
    kind, value = _parse_target(payload)
    _count_usage(request)
    _audit(kind, value, payload["purpose"])
    try:
        return await run_investigation(kind, value, payload, {})
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e))


@app.post("/api/jobs")
async def start_job(request: Request, payload: dict):
    kind, value = _parse_target(payload)
    if kind not in TARGET_CATEGORIES:
        raise HTTPException(400, f"unknown type {kind}")
    try:
        normalize(kind, value)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _count_usage(request)
    _audit(kind, value, payload["purpose"])
    if len(JOBS) >= 200:
        JOBS.pop(next(iter(JOBS)))
    if serverless():
        # No background task can outlive the response here, so do the work inside this request.
        try:
            opts = {**payload, "limit": min(int(payload.get("limit") or 150), 200)}
            result = await run_investigation(kind, value, opts, {})
        except (ValueError, TypeError) as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            return {"status": "error", "error": (str(e) or e.__class__.__name__)[:200]}
        return {"status": "done", "result": result, "type": kind, "value": value}
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
async def cases(request: Request):
    _purge_old_cases()
    return db.list_cases(_uid(request))


@app.post("/api/cases")
async def new_case(request: Request, payload: dict):
    name = str(payload.get("name", "")).strip()
    if not name or len(name) > 120:
        raise HTTPException(400, "name is required (max 120 characters)")
    return db.create_case(name, _uid(request))


@app.get("/api/cases/{case_id}")
async def case_detail(case_id: int, request: Request):
    case = db.get_case(case_id, _uid(request))
    if not case:
        raise HTTPException(404, "case not found")
    return case


@app.delete("/api/cases/{case_id}")
async def remove_case(case_id: int, request: Request):
    if not db.delete_case(case_id, _uid(request)):
        raise HTTPException(404, "case not found")
    return {"ok": True}


@app.post("/api/cases/{case_id}/items")
async def save_item(case_id: int, request: Request, payload: dict):
    result = payload.get("result")
    if not isinstance(result, dict) or not payload.get("value") or not payload.get("kind"):
        raise HTTPException(400, "kind, value and result are required")
    item = db.add_item(case_id, str(payload["kind"]), str(payload["value"]), result, str(payload.get("note", ""))[:2000],
                       _uid(request))
    if not item:
        raise HTTPException(404, "case not found")
    return item


@app.patch("/api/items/{item_id}")
async def edit_item(item_id: int, request: Request, payload: dict):
    if not db.update_note(item_id, str(payload.get("note", ""))[:2000], _uid(request)):
        raise HTTPException(404, "item not found")
    return {"ok": True}


@app.delete("/api/items/{item_id}")
async def remove_item(item_id: int, request: Request):
    if not db.delete_item(item_id, _uid(request)):
        raise HTTPException(404, "item not found")
    return {"ok": True}


@app.get("/api/cases/{case_id}/export")
async def export_case(case_id: int, request: Request, format: str = "md"):
    case = db.get_case(case_id, _uid(request))
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
    limit = max_upload()
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"file too large (max {limit // 1_000_000} MB)")
    try:
        return extras.read_exif(data)
    except Exception:
        raise HTTPException(400, "not a readable image file")
