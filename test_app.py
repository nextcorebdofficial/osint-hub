"""Offline tests: nothing here calls an external service."""
import asyncio
import os
import tempfile

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import extras  # noqa: E402
import lookups  # noqa: E402
import main  # noqa: E402

client = TestClient(main.app)


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
    d = client.post("/api/investigate", json={"value": "+8801712345678"}).json()
    assert d["type"] == "phone"
    assert d["lookup"]["valid"] and d["lookup"]["region"] == "BD"
    bad = client.post("/api/investigate", json={"value": "01712345678"}).json()
    assert "error" in bad["lookup"]


def test_validation_errors():
    assert client.post("/api/investigate", json={"value": "x", "type": "ip"}).status_code == 400
    assert client.post("/api/investigate", json={"value": "no-at", "type": "email"}).status_code == 400
    assert client.post("/api/investigate", json={"value": ""}).status_code == 400
    assert client.post("/api/jobs", json={"value": "bad/user", "type": "username"}).status_code == 400


def test_encode_ops():
    def run(op, text):
        return client.post("/api/toolbox/encode", json={"op": op, "text": text}).json()["result"]
    assert run("base64-encode", "hello") == "aGVsbG8="
    assert run("base64-decode", "aGVsbG8=") == "hello"
    assert run("hex-encode", "hi") == "6869"
    assert run("md5", "a") == "0cc175b9c0f1b6a831c399e269772661"
    assert run("identify-hash", "0cc175b9c0f1b6a831c399e269772661").startswith("MD5")
    assert client.post("/api/toolbox/encode", json={"op": "nope", "text": "x"}).status_code == 400


def test_dorks():
    r = client.get("/api/toolbox/dorks?target=example.com").json()
    assert r["type"] == "domain" and r["dorks"][0]["query"] == "site:example.com"


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
    assert anon.post("/login", data={"password": "wrong"}, follow_redirects=False).status_code == 401
    ok = anon.post("/login", data={"password": "s3cret"}, follow_redirects=False)
    assert ok.status_code == 303
    assert anon.get("/api/tools").status_code == 200


def test_rate_limit(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_HEAVY", "2")
    main._HITS.clear()
    codes = [client.post("/api/investigate", json={"value": "+8801712345678"}).status_code for _ in range(4)]
    assert codes[:2] == [200, 200] and codes[-1] == 429
    main._HITS.clear()


def test_config_reports_keys():
    c = client.get("/api/config").json()
    assert set(c["keys"]) == set(lookups.KEY_NAMES)
