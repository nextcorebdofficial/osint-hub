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
    created REAL NOT NULL
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
        _http_post(url, token, {"requests": [
            {"type": "execute", "stmt": {"sql": s}} for s in SCHEMA] + [{"type": "close"}]})
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
        for sql, args in stmts:
            cur = c.execute(sql, args)
            out.append({"rows": [dict(r) for r in cur.fetchall()] if cur.description else [],
                        "rowcount": cur.rowcount, "lastrowid": cur.lastrowid})
    return out


def _one(sql: str, args: tuple = ()) -> dict:
    return _run([(sql, args)])[0]


# ---------------------------------------------------------------- public API

def list_cases() -> list[dict]:
    return _one(
        "SELECT c.id, c.name, c.created, COUNT(i.id) AS items FROM cases c "
        "LEFT JOIN items i ON i.case_id = c.id GROUP BY c.id ORDER BY c.created DESC")["rows"]


def create_case(name: str) -> dict:
    r = _one("INSERT INTO cases (name, created) VALUES (?, ?)", (name, time.time()))
    return {"id": r["lastrowid"], "name": name}


def delete_case(case_id: int) -> bool:
    r = _run([("DELETE FROM items WHERE case_id = ?", (case_id,)),
              ("DELETE FROM cases WHERE id = ?", (case_id,))])
    return r[1]["rowcount"] > 0


def get_case(case_id: int) -> dict | None:
    case, items = _run([("SELECT * FROM cases WHERE id = ?", (case_id,)),
                        ("SELECT * FROM items WHERE case_id = ? ORDER BY created", (case_id,))])
    if not case["rows"]:
        return None
    out = dict(case["rows"][0])
    out["items"] = [{**i, "result": json.loads(i["result"])} for i in items["rows"]]
    return out


def add_item(case_id: int, kind: str, value: str, result: dict, note: str = "") -> dict | None:
    # One statement, so the existence check and the insert cannot be separated on a remote database.
    r = _one(
        "INSERT INTO items (case_id, kind, value, result, note, created) "
        "SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM cases WHERE id = ?)",
        (case_id, kind, value, json.dumps(result), note, time.time(), case_id))
    return {"id": r["lastrowid"]} if r["rowcount"] else None


def purge_older_than(days: int) -> int:
    """Delete items older than `days`, then cases that are old and have no items left."""
    cutoff = time.time() - days * 86400
    r = _run([("DELETE FROM items WHERE created < ?", (cutoff,)),
              ("DELETE FROM cases WHERE created < ? AND id NOT IN (SELECT DISTINCT case_id FROM items)",
               (cutoff,))])
    return r[0]["rowcount"] + r[1]["rowcount"]


def update_note(item_id: int, note: str) -> bool:
    return _one("UPDATE items SET note = ? WHERE id = ?", (note, item_id))["rowcount"] > 0


def delete_item(item_id: int) -> bool:
    return _one("DELETE FROM items WHERE id = ?", (item_id,))["rowcount"] > 0
