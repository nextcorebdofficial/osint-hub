"""Refresh data.json from osintframework.com and optionally check for dead links.

    python update_data.py                 # download, filter, write data.json
    python update_data.py --check-links   # also write dead_links.json (takes a few minutes)
"""
import argparse
import asyncio
import json
import re
from pathlib import Path

import httpx

SOURCE = "https://osintframework.com/arf.json"
OUT = Path(__file__).parent / "data.json"
# Facial-recognition search engines identify strangers from a photo without consent; keep them out.
EXCLUDE = re.compile(r"facecheck\.id|pimeyes\.com|lenso\.ai|faceseek", re.I)


def prune(node: dict) -> dict | None:
    if node.get("type") == "url":
        return None if EXCLUDE.search(node.get("url", "")) else node
    node["children"] = [c for c in (prune(ch) for ch in node.get("children", []) or []) if c]
    return node


def urls(node: dict):
    if node.get("type") == "url":
        yield node["name"], node.get("url", "")
    for c in node.get("children", []) or []:
        yield from urls(c)


async def check_links(tree: dict) -> list[dict]:
    sem = asyncio.Semaphore(30)
    dead = []

    async def check(client, name, url):
        async with sem:
            try:
                r = await client.head(url, follow_redirects=True, timeout=12)
                if r.status_code in (403, 405, 429):  # HEAD refused; try GET
                    r = await client.get(url, follow_redirects=True, timeout=12)
                if r.status_code >= 400 and r.status_code not in (401, 403, 429):
                    dead.append({"name": name, "url": url, "status": r.status_code})
            except Exception as e:
                dead.append({"name": name, "url": url, "error": e.__class__.__name__})

    async with httpx.AsyncClient(headers={"User-Agent": "OSINT-Hub link checker"}) as client:
        await asyncio.gather(*[check(client, n, u) for n, u in urls(tree) if u])
    return dead


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check-links", action="store_true")
    args = ap.parse_args()
    raw = httpx.get(SOURCE, timeout=60, follow_redirects=True)
    raw.raise_for_status()
    tree = prune(raw.json())
    OUT.write_text(json.dumps(tree, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {OUT.name}: {sum(1 for _ in urls(tree))} tools")
    if args.check_links:
        dead = asyncio.run(check_links(tree))
        (OUT.parent / "dead_links.json").write_text(json.dumps(dead, indent=2), encoding="utf-8")
        print(f"{len(dead)} dead or unreachable links written to dead_links.json")


if __name__ == "__main__":
    main()
