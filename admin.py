"""Operator tools: read abuse reports, list, block or delete accounts.

    python admin.py reports
    python admin.py users
    python admin.py block someone@example.com
    python admin.py unblock someone@example.com
    python admin.py delete someone@example.com

It talks to the same database as the site, so set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in your shell first
(or pass --env FILE with KEY=value lines). A blocked account is signed out within a minute.
The same thing from the Turso dashboard's SQL shell:
    UPDATE users SET blocked = strftime('%s','now') WHERE email = 'someone@example.com';
"""
import argparse
import os
import sys
import time


def _load_env(path: str) -> None:
    for line in open(path, encoding="utf-8-sig").read().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip().strip("\"'")


def _fmt(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) if ts else "-"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env", help="file with KEY=value lines (TURSO_DATABASE_URL, TURSO_AUTH_TOKEN, ...)")
    ap.add_argument("command", choices=["reports", "users", "block", "unblock", "delete"])
    ap.add_argument("email", nargs="?")
    a = ap.parse_args(argv)
    if a.env:
        _load_env(a.env)
    import db  # after the environment is set

    if a.command == "reports":
        for r in db.list_reports(100):
            print(f"#{r['id']}  {_fmt(r['created'])} UTC  [{r['category']}]  reply-to: {r['email'] or '-'}")
            print("    " + r["message"].replace("\n", "\n    ") + "\n")
        return 0
    if a.command == "users":
        for u in db.list_users():
            flags = ("blocked " if u["blocked"] else "") + ("" if u["verified"] else "unconfirmed")
            print(f"{u['id']:>5}  {u['email']:<40} joined {_fmt(u['created'])}  {flags}")
        return 0
    if not a.email:
        print("an email address is required", file=sys.stderr)
        return 2
    email = a.email.strip().lower()
    if a.command in ("block", "unblock"):
        ok = db.set_blocked(email, a.command == "block")
        print(("done: " if ok else "no such account: ") + email)
        return 0 if ok else 1
    user = db.get_user_by_email(email)
    if not user:
        print("no such account: " + email)
        return 1
    db.delete_user(user["id"])
    print("deleted account and its saved cases: " + email)
    return 0


if __name__ == "__main__":
    sys.exit(main())
