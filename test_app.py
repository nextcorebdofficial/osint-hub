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
    assert r["total"] == 1165
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
    assert r.headers["referrer-policy"] == "no-referrer"
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
