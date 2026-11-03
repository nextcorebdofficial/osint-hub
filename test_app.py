"""Offline tests: nothing here calls an external service."""
import asyncio
import json
import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["AUDIT_LOG"] = os.path.join(_tmp, "audit.log")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import db  # noqa: E402
import extras  # noqa: E402
import lookups  # noqa: E402
import main  # noqa: E402

client = TestClient(main.app)
P = "own-assets"  # a valid purpose


@pytest.mark.parametrize("value,kind", [
    ("example.com", "domain"), ("8.8.8.8", "ip"), ("a@b.com", "email"), ("johndoe", "username"),
    ("+8801712345678", "phone"), ("https://example.com/x", "url"),
    ("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", "crypto"),
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "crypto"),
])
def test_detect_type(value, kind):
    assert main.detect_type(value) == kind


def test_catalog_complete_and_face_search_excluded():
    r = client.get("/api/tools?limit=2000").json()
    assert main.BASE_TOOLS == 1165 and r["total"] == 1165 + main.EXTRA_TOOLS
    urls = " ".join(t["url"] for t in r["items"])
    for banned in ("facecheck.id", "pimeyes.com", "lenso.ai", "faceseek"):
        assert banned not in urls


def test_catalog_filters():
    r = client.get("/api/tools?category=Username&limit=100").json()
    assert r["total"] == 19
    assert all(t["category"] == "Username" for t in r["items"])
    assert client.get("/api/tools?q=whatsmyname").json()["total"] >= 1


def test_phone_lookup_offline():
    d = client.post("/api/investigate", json={"value": "+8801712345678", "purpose": P}).json()
    assert d["type"] == "phone"
    assert d["lookup"]["valid"] and d["lookup"]["region"] == "BD"
    bad = client.post("/api/investigate", json={"value": "01712345678", "purpose": P}).json()
    assert "error" in bad["lookup"]


def test_validation_errors():
    def post(**kw):
        return client.post("/api/investigate", json={"purpose": P, **kw}).status_code
    assert post(value="x", type="ip") == 400
    assert post(value="no-at", type="email") == 400
    assert post(value="") == 400
    assert client.post("/api/jobs", json={"value": "bad/user", "type": "username", "purpose": P}).status_code == 400


# ---------------------------------------------------------------- safeguards

def test_purpose_is_required():
    for body in ({"value": "example.com"}, {"value": "example.com", "purpose": ""},
                 {"value": "example.com", "purpose": "just-curious"}):
        assert client.post("/api/investigate", json=body).status_code == 400
        assert client.post("/api/jobs", json=body).status_code == 400
    assert "own-assets" in client.get("/api/config").json()["purposes"]


def test_audit_log_never_contains_the_target():
    path = os.environ["AUDIT_LOG"]
    secret_value = "+8801799990000"
    client.post("/api/investigate", json={"value": secret_value, "purpose": "journalism-research"})
    text = open(path, encoding="utf-8").read()
    assert "8801799990000" not in text
    last = json.loads(text.strip().splitlines()[-1])
    assert set(last) == {"t", "type", "purpose", "target_hmac"}
    assert last["type"] == "phone" and last["purpose"] == "journalism-research"
    assert len(last["target_hmac"]) == 16


def test_audit_log_can_be_disabled(monkeypatch):
    path = os.environ["AUDIT_LOG"]
    before = open(path, encoding="utf-8").read()
    monkeypatch.setenv("AUDIT_LOG", "")
    client.post("/api/investigate", json={"value": "+8801700000001", "purpose": P})
    monkeypatch.setenv("AUDIT_LOG", path)
    assert open(path, encoding="utf-8").read() == before


def test_security_headers():
    r = client.get("/api/health")
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "same-origin"
    assert "frame-ancestors 'none'" in client.get("/").headers["content-security-policy"]
    assert "content-security-policy" not in client.get("/docs").headers  # Swagger UI needs its CDN


def test_legal_pages(monkeypatch):
    for name, title in (("privacy", "Privacy Policy"), ("terms", "Terms of Use"),
                        ("acceptable-use", "Acceptable Use Policy"), ("disclaimer", "Disclaimer")):
        r = client.get(f"/legal/{name}")
        assert r.status_code == 200 and title in r.text
        assert "has not filled in their name" in r.text  # warns until configured
    assert client.get("/legal/nope").status_code == 404
    monkeypatch.setenv("OPERATOR_NAME", "Example Org")
    monkeypatch.setenv("OPERATOR_CONTACT", "abuse@example.org")
    monkeypatch.setenv("OPERATOR_JURISDICTION", "Examplestan")
    r = client.get("/legal/privacy")
    assert "Example Org" in r.text and "abuse@example.org" in r.text
    assert "has not filled in their name" not in r.text


def test_retention_purge():
    cid = client.post("/api/cases", json={"name": "old"}).json()["id"]
    client.post(f"/api/cases/{cid}/items", json={"kind": "domain", "value": "a.com", "result": {"x": 1}})
    assert db.purge_older_than(1) == 0  # recent data survives a 1-day retention
    assert client.get(f"/api/cases/{cid}").status_code == 200
    assert db.purge_older_than(0) >= 2  # everything is older than "now"
    assert client.get(f"/api/cases/{cid}").status_code == 404


# ---------------------------------------------------------------- toolbox

def test_encode_ops():
    def run(op, text):
        return client.post("/api/toolbox/encode", json={"op": op, "text": text}).json()["result"]
    assert run("base64-encode", "hello") == "aGVsbG8="
    assert run("base64-decode", "aGVsbG8=") == "hello"
    assert run("hex-encode", "hi") == "6869"
    assert run("md5", "a") == "0cc175b9c0f1b6a831c399e269772661"
    assert run("identify-hash", "0cc175b9c0f1b6a831c399e269772661").startswith("MD5")
    assert client.post("/api/toolbox/encode", json={"op": "nope", "text": "x"}).status_code == 400


def test_dorks_use_post_so_targets_stay_out_of_urls():
    r = client.post("/api/toolbox/dorks", json={"target": "example.com"}).json()
    assert r["type"] == "domain" and r["dorks"][0]["query"] == "site:example.com"
    assert client.get("/api/toolbox/dorks?target=example.com").status_code == 405
    assert client.post("/api/toolbox/dorks", json={"target": " "}).status_code == 400


def test_exif_rejects_non_image():
    r = client.post("/api/toolbox/exif", files={"file": ("x.txt", b"not an image")})
    assert r.status_code == 400


def test_exif_reads_plain_image():
    import io
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buf, "JPEG")
    out = extras.read_exif(buf.getvalue())
    assert out["format"] == "JPEG" and out["has_exif"] is False


# ---------------------------------------------------------------- cases

def test_case_lifecycle_and_export():
    cid = client.post("/api/cases", json={"name": "Test case"}).json()["id"]
    item = client.post(f"/api/cases/{cid}/items", json={
        "kind": "domain", "value": "example.com", "result": {"dns": {"A": ["1.1.1.1"]}}}).json()
    assert client.patch(f"/api/items/{item['id']}", json={"note": "checked"}).status_code == 200
    case = client.get(f"/api/cases/{cid}").json()
    assert case["items"][0]["note"] == "checked"
    assert "example.com" in client.get(f"/api/cases/{cid}/export?format=md").text
    assert "<pre>" in client.get(f"/api/cases/{cid}/export?format=html").text
    assert client.get(f"/api/cases/{cid}/export?format=json").json()["name"] == "Test case"
    assert client.get(f"/api/cases/{cid}/export?format=zip").status_code == 400
    assert client.delete(f"/api/cases/{cid}").status_code == 200
    assert client.get(f"/api/cases/{cid}").status_code == 404


# ---------------------------------------------------------------- security

def test_ssrf_guard_blocks_private_hosts():
    for host in ("127.0.0.1", "localhost", "10.0.0.5", "169.254.169.254"):
        assert asyncio.run(lookups.resolve_public(host)) is False
    out = asyncio.run(lookups.lookup_url(None, "http://127.0.0.1:8000/"))
    assert "blocked" in out["error"]


def test_auth_gate(monkeypatch):
    monkeypatch.setenv("APP_PASSWORD", "s3cret")
    anon = TestClient(main.app)
    assert anon.get("/api/tools").status_code == 401
    assert anon.get("/api/health").status_code == 200
    assert anon.get("/legal/terms").status_code == 200  # policies are readable before signing in
    assert anon.post("/login", data={"password": "wrong"}, follow_redirects=False).status_code == 401
    ok = anon.post("/login", data={"password": "s3cret"}, follow_redirects=False)
    assert ok.status_code == 303
    assert anon.get("/api/tools").status_code == 200


def test_rate_limit(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_HEAVY", "2")
    main._HITS.clear()
    codes = [client.post("/api/investigate", json={"value": "+8801712345678", "purpose": P}).status_code
             for _ in range(4)]
    assert codes[:2] == [200, 200] and codes[-1] == 429
    main._HITS.clear()


def test_config_reports_keys():
    c = client.get("/api/config").json()
    assert set(c["keys"]) == set(lookups.KEY_NAMES)


# ---------------------------------------------------------------- serverless and Turso

def _fake_turso(monkeypatch):
    """Stand in for Turso's HTTP API, executing the statements on an in-memory SQLite database."""
    import sqlite3
    mem = sqlite3.connect(":memory:", check_same_thread=False)
    calls = []

    def post(url, token, body):
        calls.append((url, token))
        results = []
        for r in body["requests"]:
            if r["type"] != "execute":
                results.append({"type": "ok", "response": {"type": "close"}})
                continue
            st = r["stmt"]
            args = []
            for a in st.get("args", []):
                args.append(None if a["type"] == "null" else int(a["value"]) if a["type"] == "integer" else a["value"])
            cur = mem.execute(st["sql"], args)
            mem.commit()
            cols = [{"name": d[0]} for d in cur.description or []]

            def cell(v):
                if v is None:
                    return {"type": "null"}
                if isinstance(v, int):
                    return {"type": "integer", "value": str(v)}
                if isinstance(v, float):
                    return {"type": "float", "value": v}
                return {"type": "text", "value": v}
            results.append({"type": "ok", "response": {"type": "execute", "result": {
                "cols": cols, "rows": [[cell(v) for v in row] for row in cur.fetchall()],
                "affected_row_count": max(cur.rowcount, 0),
                "last_insert_rowid": str(cur.lastrowid) if cur.lastrowid else None}}})
        return {"results": results}

    monkeypatch.setattr(db, "_http_post", post)
    monkeypatch.setattr(db, "_turso_ready", set())
    monkeypatch.setenv("TURSO_DATABASE_URL", "libsql://demo-org.turso.io")
    monkeypatch.setenv("TURSO_AUTH_TOKEN", "tok")
    return calls


def test_turso_backend_full_case_lifecycle(monkeypatch):
    calls = _fake_turso(monkeypatch)
    assert db.backend() == "turso"
    cid = client.post("/api/cases", json={"name": "remote"}).json()["id"]
    item = client.post(f"/api/cases/{cid}/items", json={
        "kind": "domain", "value": "a.com", "result": {"x": 1}, "note": "n"}).json()
    assert client.post("/api/cases/9999/items", json={"kind": "d", "value": "v", "result": {}}).status_code == 404
    case = client.get(f"/api/cases/{cid}").json()
    assert case["name"] == "remote" and case["items"][0]["result"] == {"x": 1}
    assert client.patch(f"/api/items/{item['id']}", json={"note": "edited"}).status_code == 200
    assert client.get("/api/cases").json()[0]["items"] == 1
    assert client.delete(f"/api/cases/{cid}").status_code == 200
    assert client.get(f"/api/cases/{cid}").status_code == 404
    assert all(u == "https://demo-org.turso.io/v2/pipeline" and t == "tok" for u, t in calls)
    assert client.get("/api/config").json()["storage"] == "turso"


def test_vercel_without_database_uses_temp_sqlite(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("DB_PATH")
    monkeypatch.delenv("TURSO_DATABASE_URL", raising=False)
    assert db.backend() == "sqlite-temp"
    assert db._sqlite_path().startswith(tempfile.gettempdir())


def test_serverless_jobs_finish_inside_the_request(monkeypatch):
    monkeypatch.setenv("SERVERLESS", "1")
    r = client.post("/api/jobs", json={"value": "+8801712345678", "purpose": P}).json()
    assert r["status"] == "done" and r["result"]["type"] == "phone"
    bad = client.post("/api/jobs", json={"value": "example.com", "type": "ip", "purpose": P})
    assert bad.status_code == 400  # validation errors are still real HTTP errors


def test_vercel_client_ip_comes_from_forwarded_header(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("RATE_LIMIT_HEAVY", "1")
    main._HITS.clear()
    body = {"value": "+8801712345678", "purpose": P}
    a = {"x-forwarded-for": "1.1.1.1"}
    codes = [client.post("/api/investigate", json=body, headers=a).status_code for _ in range(2)]
    other = client.post("/api/investigate", json=body, headers={"x-forwarded-for": "2.2.2.2"}).status_code
    assert codes == [200, 429] and other == 200
    main._HITS.clear()


def test_audit_falls_back_to_stdout_when_disk_is_read_only(monkeypatch, capsys):
    monkeypatch.setenv("AUDIT_LOG", os.path.join(_tmp, "no-such-dir", "audit.log"))
    main._audit("domain", "example.com", P)
    out = capsys.readouterr().out
    assert out.startswith("AUDIT {") and "example.com" not in out


def test_cases_are_off_on_public_serverless_instances(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("APP_PASSWORD", raising=False)
    monkeypatch.delenv("CASES_ENABLED", raising=False)
    assert client.get("/api/config").json()["cases"] is False
    assert client.get("/api/cases").status_code == 403
    assert client.post("/api/cases", json={"name": "x"}).status_code == 403
    monkeypatch.setenv("CASES_ENABLED", "1")  # explicit opt-in
    assert client.get("/api/cases").status_code == 200
    monkeypatch.delenv("CASES_ENABLED")
    monkeypatch.setenv("APP_PASSWORD", "pw")  # with a login they are on again (cookie needed)
    assert main.cases_enabled() is True


# ---------------------------------------------------------------- email accounts

PW = "correct horse battery"


@pytest.fixture
def accounts(monkeypatch):
    """Accounts mode with a clean database and a fresh browser for each test."""
    monkeypatch.setenv("AUTH_MODE", "accounts")
    monkeypatch.setenv("DB_PATH", os.path.join(tempfile.mkdtemp(), "acc.db"))
    monkeypatch.delenv("APP_PASSWORD", raising=False)
    monkeypatch.delenv("REGISTRATION", raising=False)
    monkeypatch.setenv("ALLOW_UNVERIFIED", "1")  # no email provider in tests unless a test turns one on
    for k in ("MAIL_PROVIDER", "MAIL_FROM", "MAIL_API_KEY", "PUBLIC_URL", "DAILY_INVESTIGATIONS"):
        monkeypatch.delenv(k, raising=False)
    main._HITS.clear()
    main._FAILS.clear()
    main._USERS.clear()
    return lambda: TestClient(main.app)


def _signup(c, email="a@example.com", pw=PW, **over):
    data = {"email": email, "password": pw, "password2": pw, "terms": "on", **over}
    return c.post("/register", data=data, follow_redirects=False)


def test_landing_is_public_and_app_is_private(accounts):
    c = accounts()
    home = c.get("/")
    assert home.status_code == 200 and "Every open-source investigation tool" in home.text
    assert c.get("/app", follow_redirects=False).status_code == 303
    assert c.get("/api/tools").status_code == 401
    assert c.get("/legal/terms").status_code == 200
    assert c.get("/docs", follow_redirects=False).status_code == 303  # even the API docs need a login


def test_register_login_logout_flow(accounts):
    c = accounts()
    r = _signup(c)
    assert r.status_code == 303 and r.headers["location"] == "/app"
    assert c.get("/app").status_code == 200
    assert c.get("/api/config").json()["user"] == "a@example.com"
    c.post("/logout")
    assert c.get("/api/tools").status_code == 401
    assert c.post("/login", data={"email": "a@example.com", "password": "wrong password!"}).status_code == 401
    ok = c.post("/login", data={"email": "A@Example.com", "password": PW}, follow_redirects=False)
    assert ok.status_code == 303 and c.get("/api/tools").status_code == 200


@pytest.mark.parametrize("over,code", [
    ({"password": "short", "password2": "short"}, 400),
    ({"password": "password1234", "password2": "password1234"}, 400),
    ({"password2": "different password"}, 400),
    ({"terms": ""}, 400),
    ({"email": "not-an-email"}, 400),
])
def test_register_rejects_bad_input(accounts, over, code):
    assert _signup(accounts(), **over).status_code == code


def test_duplicate_email_is_refused(accounts):
    _signup(accounts())
    assert _signup(accounts()).status_code == 409


def test_passwords_are_hashed_not_stored(accounts):
    _signup(accounts())
    stored = db.get_user_by_email("a@example.com")["pw"]
    assert stored.startswith("scrypt$") and PW not in stored


def test_login_locks_after_repeated_failures(accounts):
    c = accounts()
    _signup(c)
    c.post("/logout")
    codes = [c.post("/login", data={"email": "a@example.com", "password": "nope nope nope"}).status_code
             for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429
    assert c.post("/login", data={"email": "a@example.com", "password": PW}).status_code == 429  # even the right one


def test_cases_are_private_per_account(accounts):
    alice, bob = accounts(), accounts()
    _signup(alice, "alice@example.com")
    _signup(bob, "bob@example.com")
    cid = alice.post("/api/cases", json={"name": "alice only"}).json()["id"]
    item = alice.post(f"/api/cases/{cid}/items", json={"kind": "domain", "value": "a.com", "result": {}}).json()
    assert bob.get("/api/cases").json() == []
    assert bob.get(f"/api/cases/{cid}").status_code == 404
    assert bob.get(f"/api/cases/{cid}/export?format=json").status_code == 404
    assert bob.post(f"/api/cases/{cid}/items", json={"kind": "d", "value": "v", "result": {}}).status_code == 404
    assert bob.patch(f"/api/items/{item['id']}", json={"note": "hacked"}).status_code == 404
    assert bob.delete(f"/api/items/{item['id']}").status_code == 404
    assert bob.delete(f"/api/cases/{cid}").status_code == 404
    assert alice.get(f"/api/cases/{cid}").json()["items"][0]["note"] == ""


def test_account_export_and_delete(accounts):
    c = accounts()
    _signup(c)
    cid = c.post("/api/cases", json={"name": "mine"}).json()["id"]
    c.post(f"/api/cases/{cid}/items", json={"kind": "domain", "value": "a.com", "result": {"x": 1}})
    data = c.get("/api/account/export").json()
    assert data["email"] == "a@example.com" and data["cases"][0]["items"][0]["value"] == "a.com"
    assert c.request("DELETE", "/api/account", json={"password": "wrong password!"}).status_code == 403
    assert c.request("DELETE", "/api/account", json={"password": PW}).status_code == 200
    assert db.get_user_by_email("a@example.com") is None
    assert c.get("/api/tools").status_code == 401  # the old cookie no longer works


def test_registration_can_be_closed_or_invite_only(accounts, monkeypatch):
    monkeypatch.setenv("REGISTRATION", "closed")
    assert _signup(accounts()).status_code == 400
    monkeypatch.setenv("REGISTRATION", "invite")
    monkeypatch.setenv("ALLOWED_EMAILS", "friend@example.com")
    monkeypatch.setenv("ALLOWED_EMAIL_DOMAINS", "ngo.org")
    assert _signup(accounts(), "stranger@example.com").status_code == 400
    assert _signup(accounts(), "friend@example.com").status_code == 303
    assert _signup(accounts(), "staff@ngo.org").status_code == 303


def test_accounts_refuse_to_start_without_a_persistent_database(accounts, monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("DB_PATH")
    monkeypatch.setenv("APP_SECRET", "x" * 32)
    assert main.accounts_problem().startswith("no persistent database")
    assert _signup(accounts()).status_code == 503
    monkeypatch.setenv("ALLOW_TEMP_ACCOUNTS", "1")
    monkeypatch.setenv("PUBLIC_URL", "https://hub.example.org")
    assert main.accounts_problem() == ""


def test_tampered_or_foreign_sessions_are_rejected(accounts):
    c = accounts()
    _signup(c)
    tok = c.cookies.get("osint_session")
    uid, exp, sig = tok.split(".")
    for bad in (f"{uid}.{exp}.{'0' * 64}", f"999.{exp}.{sig}", f"{uid}.1.{sig}", "garbage"):
        evil = accounts()
        evil.cookies.set("osint_session", bad)
        assert evil.get("/api/tools").status_code == 401


def test_changing_the_password_invalidates_old_sessions():
    import auth
    u = {"id": 7, "pw": auth.hash_password("first password 123")}
    tok = auth.make_session("secret", u)
    assert auth.session_valid("secret", tok, u)
    assert not auth.session_valid("other-secret", tok, u)
    assert not auth.session_valid("secret", tok, {"id": 7, "pw": auth.hash_password("second password 456")})


# ---------------------------------------------------------------- hardening

def test_cross_site_writes_are_blocked():
    r = client.post("/api/toolbox/encode", json={"op": "rot13", "text": "x"}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    ok = client.post("/api/toolbox/encode", json={"op": "rot13", "text": "x"}, headers={"origin": "http://testserver"})
    assert ok.status_code == 200
    assert client.post("/api/toolbox/encode", json={"op": "rot13", "text": "x"}, headers={"origin": "null"}).status_code == 403


def test_csp_uses_a_fresh_nonce_and_no_unsafe_inline_scripts():
    a, b = client.get("/"), client.get("/")
    csp = a.headers["content-security-policy"]
    script_src = csp.split("script-src ")[1].split(";")[0]
    assert "'nonce-" in script_src and "unsafe-inline" not in script_src
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"' in a.text
    assert csp != b.headers["content-security-policy"]
    assert "object-src 'none'" in csp and "frame-ancestors 'none'" in csp


def test_extra_security_headers():
    h = client.get("/api/health").headers
    assert h["cross-origin-opener-policy"] == "same-origin" and h["cross-origin-resource-policy"] == "same-origin"
    assert "strict-transport-security" not in h  # plain http locally
    assert "strict-transport-security" in TestClient(main.app, base_url="https://testserver").get("/api/health").headers


def test_oversized_json_is_rejected():
    r = client.post("/api/toolbox/encode", content=b"x" * 10, headers={"content-length": "5000000",
                                                                         "content-type": "application/json"})
    assert r.status_code == 413


def test_bad_limit_values_are_a_400_not_a_crash():
    for bad in ("abc", [1], {"a": 1}):
        r = client.post("/api/investigate", json={"value": "+8801712345678", "purpose": P, "limit": bad})
        assert r.status_code in (200, 400)  # phone ignores limit; username must reject it
    r = client.post("/api/investigate", json={"value": "someuser", "type": "username", "purpose": P, "limit": "abc"})
    assert r.status_code == 400


def test_robots_and_security_txt(monkeypatch):
    assert "Disallow: /api/" in client.get("/robots.txt").text
    monkeypatch.delenv("OPERATOR_CONTACT", raising=False)
    assert client.get("/.well-known/security.txt").status_code == 404
    monkeypatch.setenv("OPERATOR_CONTACT", "security@example.org")
    body = client.get("/.well-known/security.txt").text
    assert "Contact: mailto:security@example.org" in body and "Expires:" in body


# ---------------------------------------------------------------- email verification, reset, limits

@pytest.fixture
def mailbox(accounts, monkeypatch):
    """Accounts with email turned on; every message lands in a list instead of the network."""
    sent = []
    monkeypatch.delenv("ALLOW_UNVERIFIED", raising=False)
    monkeypatch.setenv("MAIL_PROVIDER", "resend")
    monkeypatch.setenv("MAIL_API_KEY", "k")
    monkeypatch.setenv("MAIL_FROM", "NextCore BD <no-reply@example.org>")
    monkeypatch.setenv("PUBLIC_URL", "https://hub.example.org")
    monkeypatch.setattr(main.mailer, "send", lambda to, subject, text, html="": sent.append((to, subject, text)) or True)
    main._MAILS.clear()
    return accounts, sent


def _link(sent, i=-1):
    import re
    return re.search(r"https://hub\.example\.org(/\S+)", sent[i][2]).group(1)


def test_signup_sends_a_link_and_needs_it_before_login(mailbox):
    make, sent = mailbox
    c = make()
    r = _signup(c)
    assert r.status_code == 200 and "Check your email" in r.text  # no session yet
    assert c.get("/api/tools").status_code == 401
    assert sent[-1][0] == "a@example.com" and "NextCore BD" in sent[-1][1]
    blocked = c.post("/login", data={"email": "a@example.com", "password": PW})
    assert blocked.status_code == 403 and "Confirm your email first" in blocked.text
    ok = c.get(_link(sent), follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/app"
    assert c.get("/api/tools").status_code == 200
    c.post("/logout")
    assert c.post("/login", data={"email": "a@example.com", "password": PW}, follow_redirects=False).status_code == 303


def test_verification_link_is_bound_to_the_address_and_expires(mailbox):
    import auth
    make, sent = mailbox
    _signup(make())
    user = db.get_user_by_email("a@example.com")
    tok = auth.make_link_token(main.SECRET, "verify", user)
    assert auth.link_token_valid(main.SECRET, "verify", tok, user)
    assert not auth.link_token_valid(main.SECRET, "reset", tok, user)  # a verify link cannot reset a password
    assert not auth.link_token_valid("other", "verify", tok, user)
    uid, exp, sig = tok.split(".")
    assert not auth.link_token_valid(main.SECRET, "verify", f"{uid}.1.{sig}", user)
    assert make().get("/verify?token=junk").status_code == 400


def test_password_reset_works_once_and_signs_out_old_sessions(mailbox):
    make, sent = mailbox
    c = make()
    _signup(c)
    c.get(_link(sent))
    assert c.get("/api/tools").status_code == 200
    r = make().post("/forgot", data={"email": "a@example.com"})
    assert "If that address has an account" in r.text and len(sent) == 2
    link = _link(sent)
    assert "/reset?token=" in link
    other = make()
    assert other.get(link).status_code == 200
    new = "a brand new passphrase"
    assert other.post("/reset", data={"token": link.split("=")[1], "password": new, "password2": new}).status_code == 200
    assert c.get("/api/tools").status_code == 401  # the old session died with the old password
    assert other.get(link).status_code == 400  # the link cannot be used twice
    assert make().post("/login", data={"email": "a@example.com", "password": PW}).status_code == 401
    assert make().post("/login", data={"email": "a@example.com", "password": new}, follow_redirects=False).status_code == 303


def test_forgot_does_not_reveal_whether_an_account_exists(mailbox):
    make, sent = mailbox
    a = make().post("/forgot", data={"email": "nobody@example.com"})
    _signup(make())
    n = len(sent)
    b = make().post("/forgot", data={"email": "a@example.com"})
    import re
    strip = lambda s: re.sub(r'nonce="[^"]+"', "", s)  # the CSP nonce differs on every response
    assert a.status_code == b.status_code == 200 and strip(a.text) == strip(b.text)
    assert len(sent) == n + 1  # only the real address got a message


def test_emails_to_one_address_are_throttled(mailbox):
    make, sent = mailbox
    _signup(make())
    for _ in range(6):
        make().post("/forgot", data={"email": "a@example.com"})
    assert len(sent) == 3  # signup mail + two more, then the hourly cap


def test_email_links_never_use_the_host_header(mailbox):
    make, sent = mailbox
    make().post("/register", data={"email": "x@example.com", "password": PW, "password2": PW, "terms": "on"},
                headers={"host": "evil.example"})
    assert "evil.example" not in sent[-1][2] and "hub.example.org" in sent[-1][2]


def test_public_hosts_need_a_fixed_public_url(accounts, monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("APP_SECRET", "x" * 32)
    monkeypatch.setenv("ALLOW_TEMP_ACCOUNTS", "1")
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    assert "PUBLIC_URL" in main.accounts_problem()


def test_signup_is_unavailable_without_email_unless_allowed(accounts, monkeypatch):
    monkeypatch.delenv("ALLOW_UNVERIFIED")
    monkeypatch.delenv("MAIL_PROVIDER", raising=False)
    assert "email sending is not configured" in main.accounts_problem()
    assert _signup(accounts()).status_code == 503


def test_daily_investigation_limit(accounts, monkeypatch):
    monkeypatch.setenv("DAILY_INVESTIGATIONS", "2")
    c = accounts()
    _signup(c)
    body = {"value": "+8801712345678", "purpose": P}
    codes = [c.post("/api/investigate", json=body).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert c.get("/api/config").json()["daily_limit"] == 2
    monkeypatch.setenv("DAILY_INVESTIGATIONS", "0")  # 0 switches the cap off
    assert c.post("/api/investigate", json=body).status_code == 200


def test_mailer_providers_build_the_right_requests(monkeypatch):
    import mailer
    calls = []

    class R:
        status_code = 202

    monkeypatch.setattr(mailer.httpx, "post", lambda url, **kw: calls.append((url, kw)) or R())
    monkeypatch.setenv("MAIL_FROM", "NextCore BD <no-reply@example.org>")
    monkeypatch.setenv("MAIL_API_KEY", "secret")
    monkeypatch.setenv("MAIL_PROVIDER", "resend")
    assert mailer.send("u@example.com", "Hi", "body") is True
    assert calls[-1][0] == "https://api.resend.com/emails"
    assert calls[-1][1]["headers"]["Authorization"] == "Bearer secret"
    assert calls[-1][1]["json"]["to"] == ["u@example.com"]
    monkeypatch.setenv("MAIL_PROVIDER", "brevo")
    assert mailer.send("u@example.com", "Hi", "body") is True
    assert calls[-1][0] == "https://api.brevo.com/v3/smtp/email"
    assert calls[-1][1]["json"]["sender"] == {"name": "NextCore BD", "email": "no-reply@example.org"}
    monkeypatch.setenv("MAIL_PROVIDER", "none")
    assert mailer.send("u@example.com", "Hi", "body") is False  # unconfigured never raises


def test_brand_appears_on_public_pages(accounts):
    c = accounts()
    assert "NextCore BD" in c.get("/").text
    assert "NextCore BD" in c.get("/login").text
    assert "NextCore BD" in c.get("/legal/privacy").text


def test_accounts_and_usage_work_on_turso(monkeypatch):
    _fake_turso(monkeypatch)
    uid = db.create_user("t@example.com", "hash", 1.0)
    assert uid and db.create_user("t@example.com", "hash", 1.0) is None
    assert db.get_user_by_email("t@example.com")["verified"] is None
    assert db.set_verified(uid) and not db.set_verified(uid)
    assert [db.bump_usage(uid, "2026-11-03", 2) for _ in range(3)] == [True, True, False]
    assert db.bump_usage(uid, "2026-11-04", 2)  # a new day starts again
    cid = db.create_case("c", uid)["id"]
    assert db.get_case(cid, uid)["name"] == "c" and db.get_case(cid, uid + 1) is None
    assert db.delete_user(uid) and db.get_user(uid) is None and db.list_cases(uid) == []


def test_signup_reports_when_the_email_could_not_be_sent(mailbox, monkeypatch):
    make, sent = mailbox
    monkeypatch.setattr(main.mailer, "send", lambda *a, **k: False)
    c = make()
    r = _signup(c)
    assert r.status_code == 202 and "email not sent" in r.text and "Send a new confirmation link" in r.text
    assert db.get_user_by_email("a@example.com") is not None  # the account exists; they can ask for a new link
    monkeypatch.setattr(main.mailer, "send", lambda to, subject, text, html="": sent.append((to, subject, text)) or True)
    main._MAILS.clear()
    assert "we sent a new link" in c.post("/resend", data={"email": "a@example.com"}).text
    assert sent and "/verify?token=" in sent[-1][2]


def test_mailer_logs_provider_errors_without_the_key(monkeypatch, capsys):
    import mailer

    class R:
        status_code = 403
        text = '{"message":"domain not verified"}'

    monkeypatch.setattr(mailer.httpx, "post", lambda url, **kw: R())
    monkeypatch.setenv("MAIL_PROVIDER", "resend")
    monkeypatch.setenv("MAIL_API_KEY", "super-secret-key")
    monkeypatch.setenv("MAIL_FROM", "x <no-reply@example.org>")
    assert mailer.send("u@example.com", "s", "b") is False
    out = capsys.readouterr().out
    assert "MAIL FAILED" in out and "403" in out and "domain not verified" in out and "super-secret-key" not in out


def test_browser_form_posts_work_with_the_real_headers_browsers_send(accounts):
    """Regression: a strict referrer policy made browsers send 'Origin: null', which used to block sign-up."""
    c = accounts()
    same = {"sec-fetch-site": "same-origin", "origin": "null"}
    r = c.post("/register", data={"email": "b@example.com", "password": PW, "password2": PW, "terms": "on"},
               headers=same, follow_redirects=False)
    assert r.status_code == 303
    assert c.get("/login", headers={"sec-fetch-site": "same-origin"}, follow_redirects=False).status_code == 303
    cross = c.post("/login", data={"email": "b@example.com", "password": PW}, headers={"sec-fetch-site": "cross-site"})
    assert cross.status_code == 403
    sameSite = c.post("/login", data={"email": "b@example.com", "password": PW}, headers={"sec-fetch-site": "same-site"})
    assert sameSite.status_code == 403  # a sibling subdomain is not us
    assert client.get("/login").headers["referrer-policy"] == "same-origin"


# ---------------------------------------------------------------- extra catalog entries, SecurityTrails

def test_extra_tools_are_merged_into_the_catalog_without_duplicates():
    cats = {c["name"]: c["count"] for c in client.get("/api/categories").json()}
    assert cats["Directories & Catalogs"] == 6 and cats["Automated Engines & Suites"] >= 4
    names = [t["name"] for t in client.get("/api/tools?category=Directories%20%26%20Catalogs&limit=50").json()["items"]]
    assert "IntelTechniques Tools" in names and "OSINT.link" in names
    key = lambda t: (t["url"].rstrip("/").lower(), t["category"])
    base, extra = {key(t) for t in main.TOOLS[:main.BASE_TOOLS]}, [key(t) for t in main.TOOLS[main.BASE_TOOLS:]]
    assert len(extra) == len(set(extra)) and not base & set(extra)  # extras never repeat a listed tool
    assert [t["id"] for t in main.TOOLS] == list(range(len(main.TOOLS)))
    assert "Automated Engines & Suites" in main.TARGET_CATEGORIES["domain"]


def test_vercel_ships_the_extra_catalog_file():
    cfg = json.load(open(os.path.join(os.path.dirname(main.__file__), "vercel.json"), encoding="utf-8"))
    assert "extra_tools.json" in cfg["builds"][0]["config"]["includeFiles"]


def test_securitytrails_lookup(monkeypatch):
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    assert "set SECURITYTRAILS_API_KEY" in asyncio.run(lookups.securitytrails(None, "a.com"))["info"]
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "k")
    seen = []

    async def fake(client, url, **kw):
        seen.append((url, kw.get("headers", {}).get("APIKEY")))
        if url.endswith("/subdomains"):
            return {"subdomains": ["www", "api"]}
        return {"records": [{"values": [{"ip": "1.2.3.4"}], "first_seen": "2020-01-01", "last_seen": "2021-01-01",
                             "organizations": ["Org"]}]}

    monkeypatch.setattr(lookups, "_get_json", fake)
    out = asyncio.run(lookups.securitytrails(None, "a.com"))
    assert out["subdomains"] == ["api.a.com", "www.a.com"] and out["subdomain_count"] == 2
    assert out["a_record_history"][0]["ips"] == ["1.2.3.4"]
    assert all(k == "k" for _, k in seen)

    async def down(client, url, **kw):
        return None

    monkeypatch.setattr(lookups, "_get_json", down)
    assert "request failed" in asyncio.run(lookups.securitytrails(None, "a.com"))["error"]
    assert lookups.configured_keys()["SECURITYTRAILS_API_KEY"] is True


# ---------------------------------------------------------------- brand

def test_logo_and_favicon_are_served_publicly(accounts):
    c = accounts()
    for path in ("/favicon.svg", "/logo.svg"):
        r = c.get(path)
        assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml")
        assert "<svg" in r.text and "#5b21b6" in r.text
        assert "max-age" in r.headers["cache-control"]
    assert "NextCore BD" in c.get("/logo.svg").text
    assert c.get("/favicon.ico", follow_redirects=False).headers["location"] == "/favicon.svg"


def test_pages_use_the_purple_brand_and_show_the_logo(accounts):
    c = accounts()
    for path in ("/", "/login", "/register", "/forgot", "/legal/terms"):
        html = c.get(path).text
        assert "#7c3aed" in html and 'class="mark"' in html and 'rel="icon"' in html
        assert "#1f6feb" not in html and "#4493f8" not in html  # the old blue is gone
    _signup(c)
    app = c.get("/app").text
    assert "--btn:#7c3aed" in app and "#1f6feb" not in app and 'class="mark"' in app


def test_recon_tools_are_listed_with_an_authorisation_warning():
    items = client.get("/api/tools?category=Recon%20%26%20Attack%20Surface&limit=100").json()["items"]
    names = " ".join(t["name"] for t in items)
    for tool in ("subfinder", "httpx", "naabu", "nuclei", "Amass", "Masscan", "Nmap"):
        assert tool in names
    for t in items:
        if t["name"].split()[0] in ("naabu", "nuclei", "Masscan", "Nmap", "RustScan", "httpx", "katana"):
            assert "permission" in t["description"]  # active scanners say so
    assert "Recon & Attack Surface" in main.TARGET_CATEGORIES["domain"]
    assert "Recon & Attack Surface" in main.TARGET_CATEGORIES["ip"]
