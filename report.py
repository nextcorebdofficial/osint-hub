"""Case report export (Markdown, HTML for print-to-PDF)."""
import html
import json
import time


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))


def to_markdown(case: dict) -> str:
    lines = [f"# {case['name']}", "", f"Created {_ts(case['created'])} - {len(case['items'])} item(s)", ""]
    for i in case["items"]:
        lines += [f"## {i['kind']}: {i['value']}", f"_{_ts(i['created'])}_", ""]
        if i["note"]:
            lines += [f"**Note:** {i['note']}", ""]
        lines += ["```json", json.dumps(i["result"], indent=2, ensure_ascii=False), "```", ""]
    return "\n".join(lines)


def to_html(case: dict) -> str:
    parts = [
        "<!doctype html><meta charset='utf-8'>",
        f"<title>{html.escape(case['name'])}</title>",
        "<style>body{font:14px/1.5 system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px}"
        "pre{background:#f4f4f4;padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-word}"
        "h2{margin-top:28px;border-bottom:1px solid #ccc}</style>",
        f"<h1>{html.escape(case['name'])}</h1>",
        f"<p>Created {_ts(case['created'])} &middot; {len(case['items'])} item(s) &middot; use Print &rarr; Save as PDF</p>",
    ]
    for i in case["items"]:
        parts.append(f"<h2>{html.escape(i['kind'])}: {html.escape(i['value'])}</h2>")
        parts.append(f"<p><em>{_ts(i['created'])}</em></p>")
        if i["note"]:
            parts.append(f"<p><strong>Note:</strong> {html.escape(i['note'])}</p>")
        parts.append(f"<pre>{html.escape(json.dumps(i['result'], indent=2, ensure_ascii=False))}</pre>")
    return "".join(parts)
