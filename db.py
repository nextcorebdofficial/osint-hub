"""SQLite storage for cases and saved investigation results."""
import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    result TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL
);
"""


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(os.environ.get("DB_PATH") or str(Path(__file__).parent / "osint.db"))
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c


def list_cases() -> list[dict]:
    with closing(_conn()) as c:
        rows = c.execute(
            "SELECT c.id, c.name, c.created, COUNT(i.id) AS items FROM cases c "
            "LEFT JOIN items i ON i.case_id = c.id GROUP BY c.id ORDER BY c.created DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def create_case(name: str) -> dict:
    with closing(_conn()) as c, c:
        cur = c.execute("INSERT INTO cases (name, created) VALUES (?, ?)", (name, time.time()))
        return {"id": cur.lastrowid, "name": name}


def delete_case(case_id: int) -> bool:
    with closing(_conn()) as c, c:
        c.execute("DELETE FROM items WHERE case_id = ?", (case_id,))
        return c.execute("DELETE FROM cases WHERE id = ?", (case_id,)).rowcount > 0


def get_case(case_id: int) -> dict | None:
    with closing(_conn()) as c:
        case = c.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not case:
            return None
        items = c.execute("SELECT * FROM items WHERE case_id = ? ORDER BY created", (case_id,)).fetchall()
    out = dict(case)
    out["items"] = [{**dict(i), "result": json.loads(i["result"])} for i in items]
    return out


def add_item(case_id: int, kind: str, value: str, result: dict, note: str = "") -> dict | None:
    with closing(_conn()) as c, c:
        if not c.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone():
            return None
        cur = c.execute(
            "INSERT INTO items (case_id, kind, value, result, note, created) VALUES (?,?,?,?,?,?)",
            (case_id, kind, value, json.dumps(result), note, time.time()),
        )
        return {"id": cur.lastrowid}


def purge_older_than(days: int) -> int:
    """Delete items older than `days`, then cases that are old and have no items left."""
    cutoff = time.time() - days * 86400
    with closing(_conn()) as c, c:
        n = c.execute("DELETE FROM items WHERE created < ?", (cutoff,)).rowcount
        n += c.execute(
            "DELETE FROM cases WHERE created < ? AND id NOT IN (SELECT DISTINCT case_id FROM items)",
            (cutoff,)).rowcount
    return n


def update_note(item_id: int, note: str) -> bool:
    with closing(_conn()) as c, c:
        return c.execute("UPDATE items SET note = ? WHERE id = ?", (note, item_id)).rowcount > 0


def delete_item(item_id: int) -> bool:
    with closing(_conn()) as c, c:
        return c.execute("DELETE FROM items WHERE id = ?", (item_id,)).rowcount > 0
