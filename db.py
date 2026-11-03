"""Storage for cases and saved investigation results.

Three backends, chosen from the environment:
- Turso (libSQL over HTTPS) when TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are set. Persistent and works
  on serverless hosts such as Vercel, where the file system is read-only and short-lived.
- A SQLite file at DB_PATH, or osint.db next to this file. The default for laptops, Docker and VPS.
- A SQLite file in the temp directory on Vercel without Turso. It works but is wiped regularly.
"""
import json
import os
import sqlite3
import tempfile
import time
from contextlib import closing
from pathlib import Path

import httpx

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created REAL NOT NULL,
    user_id INTEGER
)""",
    """CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    pw TEXT NOT NULL,
    created REAL NOT NULL,
    terms REAL NOT NULL,
    verified REAL
)""",
    """CREATE TABLE IF NOT EXISTS usage (
    uid INTEGER NOT NULL,
    day TEXT NOT NULL,
    n INTEGER NOT NULL,
    PRIMARY KEY (uid, day)
)""",
    """CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    result TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL
)""",
]

_turso_ready: set[str] = set()


def backend() -> str:
    """'turso', 'sqlite' or 'sqlite-temp' (data will not survive)."""
    if os.environ.get("TURSO_DATABASE_URL") and os.environ.get("TURSO_AUTH_TOKEN"):
        return "turso"
    if not os.environ.get("DB_PATH") and os.environ.get("VERCEL"):
        return "sqlite-temp"
    return "sqlite"


def _sqlite_path() -> str:
    if os.environ.get("DB_PATH"):
        return os.environ["DB_PATH"]
    if os.environ.get("VERCEL"):
        return str(Path(tempfile.gettempdir()) / "osint.db")
    return str(Path(__file__).parent / "osint.db")


# ---------------------------------------------------------------- Turso over HTTP

def _turso_url() -> str:
    url = os.environ["TURSO_DATABASE_URL"].strip().rstrip("/")
    if url.startswith("libsql://"):
        url = "https://" + url[len("libsql://"):]
    return url + "/v2/pipeline"


def _http_post(url: str, token: str, body: dict) -> dict:
    r = httpx.post(url, json=body, headers={"Authorization": f"Bearer {token}"}, timeout=15)
    if r.status_code >= 400:
        raise RuntimeError(f"database error {r.status_code}")
    return r.json()


def _arg(v) -> dict:
    if v is None:
        return {"type": "null"}
    if isinstance(v, bool):
        return {"type": "integer", "value": str(int(v))}
    if isinstance(v, int):
        return {"type": "integer", "value": str(v)}
    if isinstance(v, float):
        return {"type": "float", "value": v}
    return {"type": "text", "value": str(v)}


def _val(cell: dict):
    t = cell.get("type")
    if t == "null":
        return None
    if t == "integer":
        return int(cell["value"])
    if t == "float":
        return float(cell["value"])
    return cell.get("value")


def _turso_run(stmts: list[tuple[str, tuple]]) -> list[dict]:
    """Run statements in one round trip, in order. Returns {rows, rowcount, lastrowid} for each."""
    url, token = _turso_url(), os.environ["TURSO_AUTH_TOKEN"]
    if url not in _turso_ready:
        # One round trip for the schema and both column checks; a second only for an old database.
        reqs = [{"type": "execute", "stmt": {"sql": s}} for s in SCHEMA]
        reqs += [{"type": "execute", "stmt": {"sql": "PRAGMA table_info(cases)"}},
                 {"type": "execute", "stmt": {"sql": "PRAGMA table_info(users)"}}, {"type": "close"}]
        res = _http_post(url, token, {"requests": reqs})["results"]
        n = len(SCHEMA)

        def names(r):
            return [row[1].get("value") for row in r["response"]["result"].get("rows", [])]

        alters = []
        if "user_id" not in names(res[n]):  # databases created before accounts existed
            alters.append("ALTER TABLE cases ADD COLUMN user_id INTEGER")
        if "verified" not in names(res[n + 1]):  # created before email confirmation existed
            alters.append("ALTER TABLE users ADD COLUMN verified REAL")
        if alters:
            _http_post(url, token, {"requests": [
                {"type": "execute", "stmt": {"sql": s}} for s in alters] + [{"type": "close"}]})
        _turso_ready.add(url)
    body = {"requests": [
        {"type": "execute", "stmt": {"sql": sql, "args": [_arg(a) for a in args]}} for sql, args in stmts
    ] + [{"type": "close"}]}
    data = _http_post(url, token, body)
    out = []
    for res in data["results"][:len(stmts)]:
        if res.get("type") != "ok":
            raise RuntimeError("database error: " + str(res.get("error", {}).get("message", "unknown")))
        r = res["response"]["result"]
        cols = [c["name"] for c in r.get("cols", [])]
        rid = r.get("last_insert_rowid")
        out.append({
            "rows": [dict(zip(cols, (_val(c) for c in row))) for row in r.get("rows", [])],
            "rowcount": r.get("affected_row_count", 0),
            "lastrowid": int(rid) if rid is not None else None,
        })
    return out


# ---------------------------------------------------------------- one entry point for both engines

def _run(stmts: list[tuple[str, tuple]]) -> list[dict]:
    if backend() == "turso":
        return _turso_run(stmts)
    out = []
    c = sqlite3.connect(_sqlite_path())
    c.row_factory = sqlite3.Row
    with closing(c), c:
        for sql in SCHEMA:
            c.execute(sql)
        if "user_id" not in [r[1] for r in c.execute("PRAGMA table_info(cases)")]:
            c.execute("ALTER TABLE cases ADD COLUMN user_id INTEGER")  # created before accounts existed
        if "verified" not in [r[1] for r in c.execute("PRAGMA table_info(users)")]:
            c.execute("ALTER TABLE users ADD COLUMN verified REAL")  # created before email verification
        for sql, args in stmts:
            cur = c.execute(sql, args)
            out.append({"rows": [dict(r) for r in cur.fetchall()] if cur.description else [],
                        "rowcount": cur.rowcount, "lastrowid": cur.lastrowid})
    return out


def _one(sql: str, args: tuple = ()) -> dict:
    return _run([(sql, args)])[0]


# ---------------------------------------------------------------- public API
#
# `uid` scopes every case query to one account. None means "no accounts" (single-user or shared
# password mode); `user_id IS ?` matches NULL as well as a number, so both modes use one query.

def list_cases(uid: int | None = None) -> list[dict]:
    return _one(
        "SELECT c.id, c.name, c.created, COUNT(i.id) AS items FROM cases c "
        "LEFT JOIN items i ON i.case_id = c.id WHERE c.user_id IS ? GROUP BY c.id ORDER BY c.created DESC",
        (uid,))["rows"]


def create_case(name: str, uid: int | None = None) -> dict:
    r = _one("INSERT INTO cases (name, created, user_id) VALUES (?, ?, ?)", (name, time.time(), uid))
    return {"id": r["lastrowid"], "name": name}


def delete_case(case_id: int, uid: int | None = None) -> bool:
    r = _run([("DELETE FROM items WHERE case_id = ? AND case_id IN "
               "(SELECT id FROM cases WHERE id = ? AND user_id IS ?)", (case_id, case_id, uid)),
              ("DELETE FROM cases WHERE id = ? AND user_id IS ?", (case_id, uid))])
    return r[1]["rowcount"] > 0


def get_case(case_id: int, uid: int | None = None) -> dict | None:
    case, items = _run([
        ("SELECT * FROM cases WHERE id = ? AND user_id IS ?", (case_id, uid)),
        ("SELECT i.* FROM items i JOIN cases c ON c.id = i.case_id "
         "WHERE i.case_id = ? AND c.user_id IS ? ORDER BY i.created", (case_id, uid))])
    if not case["rows"]:
        return None
    out = {k: v for k, v in case["rows"][0].items() if k != "user_id"}
    out["items"] = [{**i, "result": json.loads(i["result"])} for i in items["rows"]]
    return out


def add_item(case_id: int, kind: str, value: str, result: dict, note: str = "",
             uid: int | None = None) -> dict | None:
    # One statement, so the existence check and the insert cannot be separated on a remote database.
    r = _one(
        "INSERT INTO items (case_id, kind, value, result, note, created) "
        "SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM cases WHERE id = ? AND user_id IS ?)",
        (case_id, kind, value, json.dumps(result), note, time.time(), case_id, uid))
    return {"id": r["lastrowid"]} if r["rowcount"] else None


def purge_older_than(days: int) -> int:
    """Delete items older than `days`, then cases that are old and have no items left."""
    cutoff = time.time() - days * 86400
    r = _run([("DELETE FROM items WHERE created < ?", (cutoff,)),
              ("DELETE FROM cases WHERE created < ? AND id NOT IN (SELECT DISTINCT case_id FROM items)",
               (cutoff,))])
    return r[0]["rowcount"] + r[1]["rowcount"]


def update_note(item_id: int, note: str, uid: int | None = None) -> bool:
    return _one("UPDATE items SET note = ? WHERE id = ? AND case_id IN "
                "(SELECT id FROM cases WHERE user_id IS ?)", (note, item_id, uid))["rowcount"] > 0


def delete_item(item_id: int, uid: int | None = None) -> bool:
    return _one("DELETE FROM items WHERE id = ? AND case_id IN (SELECT id FROM cases WHERE user_id IS ?)",
                (item_id, uid))["rowcount"] > 0


# ---------------------------------------------------------------- accounts

def create_user(email: str, pw_hash: str, terms_at: float) -> int | None:
    """Returns the new id, or None when the email is already registered."""
    try:
        r = _one("INSERT INTO users (email, pw, created, terms) "
                 "SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = ?)",
                 (email, pw_hash, time.time(), terms_at, email))
    except (sqlite3.IntegrityError, RuntimeError) as e:  # lost a race against the UNIQUE constraint
        if "UNIQUE" in str(e).upper():
            return None
        raise
    return r["lastrowid"] if r["rowcount"] else None


def set_verified(uid: int) -> bool:
    return _one("UPDATE users SET verified = ? WHERE id = ? AND verified IS NULL", (time.time(), uid))["rowcount"] > 0


def set_password(uid: int, pw_hash: str) -> bool:
    return _one("UPDATE users SET pw = ? WHERE id = ?", (pw_hash, uid))["rowcount"] > 0


def bump_usage(uid: int, day: str, limit: int) -> bool:
    """Count one investigation for `uid` on `day` (YYYY-MM-DD). False when the daily limit is already used up."""
    r = _one("INSERT INTO usage (uid, day, n) VALUES (?, ?, 1) "
             "ON CONFLICT(uid, day) DO UPDATE SET n = n + 1 WHERE n < ?", (uid, day, limit))
    return r["rowcount"] > 0


def get_user_by_email(email: str) -> dict | None:
    rows = _one("SELECT * FROM users WHERE email = ?", (email,))["rows"]
    return rows[0] if rows else None


def get_user(uid: int) -> dict | None:
    rows = _one("SELECT * FROM users WHERE id = ?", (uid,))["rows"]
    return rows[0] if rows else None


def delete_user(uid: int) -> bool:
    """Remove the account and everything it saved."""
    r = _run([("DELETE FROM items WHERE case_id IN (SELECT id FROM cases WHERE user_id = ?)", (uid,)),
              ("DELETE FROM cases WHERE user_id = ?", (uid,)),
              ("DELETE FROM usage WHERE uid = ?", (uid,)),
              ("DELETE FROM users WHERE id = ?", (uid,))])
    return r[3]["rowcount"] > 0


def export_user(uid: int) -> dict:
    user = get_user(uid) or {}
    cases = [get_case(c["id"], uid) for c in list_cases(uid)]
    return {"email": user.get("email"), "created": user.get("created"), "verified": user.get("verified"),
            "terms_accepted": user.get("terms"), "cases": cases}
