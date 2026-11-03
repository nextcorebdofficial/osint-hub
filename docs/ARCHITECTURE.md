# Architecture

This page explains how OSINT Hub is built, so you can change it with confidence.

## Big picture

```
Browser (templates/index.html, plain JavaScript)
   |  JSON over HTTP
   v
FastAPI app (main.py)
   |-- middleware: login check + per-IP rate limit
   |-- catalog: data.json -> flat list of tools in memory
   |-- investigation service: validate -> cache -> lookups -> result
   |-- jobs: background asyncio tasks with progress
   |-- cases API -> db.py (SQLite) -> report.py (export)
   `-- toolbox API -> extras.py (encode, dorks, EXIF)
         |
         v
   lookups.py -> public services (DNS, RDAP, crt.sh, Wayback, GLEIF, ...)
```

There is no separate front-end build. The UI is one HTML file with inline CSS and JavaScript. That keeps the project easy to read and easy to host.

## Files

| File | Role |
|---|---|
| `main.py` | App setup, `.env` loading, catalog loading, target detection and validation, investigation service, jobs, cache, login, rate limit, all routes |
| `lookups.py` | One function per target type, plus the keyed integrations. All network calls to external services live here. |
| `extras.py` | Encoders and hashes, hash identifier, dork templates, EXIF reader (Pillow) |
| `db.py` | SQLite access: cases and items. Opens a short-lived connection per call. |
| `report.py` | Turns a case into Markdown or HTML |
| `data.json` | The OSINT Framework tree, already filtered |
| `update_data.py` | Re-downloads and filters `data.json`, optional dead-link check |
| `templates/index.html` | Whole UI |
| `templates/login.html` | Password page |
| `test_app.py` | Offline tests |

## Request flow for an investigation

1. The browser sends `POST /api/jobs` with `{value, type?, region?}`.
2. `main.py` detects the type (`detect_type`) if none was given, then validates and normalises the value (`normalize`). Bad input returns HTTP 400 before any work starts.
3. A job record is created and an `asyncio` task starts. The browser gets a job id and polls `GET /api/jobs/{id}` about every 700 ms.
4. The task calls `run_investigation`. It looks in the cache (key: type, value, limit, region). On a miss it calls the matching function in `lookups.py` with a shared `httpx.AsyncClient`.
5. Inside a lookup, independent requests run in parallel with `asyncio.gather`. A failed external call returns nothing for that part instead of failing the whole lookup.
6. The result plus the list of relevant catalog tools is stored on the job. The browser renders it.

The catalog tools shown for a target come from `TARGET_CATEGORIES` in `main.py`, which maps each target type to framework categories. Change that mapping to change which tools are suggested.

## Target detection

`detect_type` tries, in order: IP address, email, URL (starts with http/https), phone-like number, crypto address, domain, and falls back to username. You can always override the type in the UI.

## Security design

- **Login:** if `APP_PASSWORD` is set, every route except `/login` and `/api/health` requires a signed cookie. The cookie value is an HMAC of the password with `APP_SECRET`, so changing the password invalidates old sessions.
- **Rate limit:** a sliding one-minute window per client IP. Heavy endpoints (start investigation, EXIF upload) have a lower limit than the rest. Counters live in memory.
- **SSRF guard:** `lookup_url` resolves the host and refuses anything that is not a globally routable address (loopback, private ranges, link-local such as cloud metadata addresses). It follows redirects manually and checks every hop. Response bodies are capped at 200 KB.
- **Input validation:** usernames are restricted to letters, digits, `.`, `_`, `-` and URL-encoded before being placed in site URLs.
- **Output:** the UI escapes everything it inserts into the page. Reports escape HTML.
- **Uploads:** EXIF files are limited to 15 MB, processed in memory, never written to disk.

## Data model

```
cases(id, name, created)
items(id, case_id, kind, value, result JSON, note, created)
```

Deleting a case deletes its items. The database file is created on first use at `DB_PATH` (default `osint.db` next to `main.py`).

## Adding a new lookup

1. Write `async def lookup_thing(client, value)` in `lookups.py`. Return a plain dict. Use `_get_json` for simple JSON APIs.
2. Add the new type to `TARGET_CATEGORIES`, `detect_type` and `normalize` in `main.py` if it is a new kind of target.
3. Add a branch for it in `run_investigation` in `main.py`.
4. Add a test in `test_app.py`. Keep tests offline: test validation and parsing, not live services.
5. Document it in the README table.

## Design decisions

- **Why FastAPI:** async I/O fits "ask ten services at once", automatic API docs, easy to test.
- **Why SQLite:** zero setup, enough for a single-server tool, trivial to back up (copy one file).
- **Why no front-end framework:** one file anyone can read; no build step.
- **Why background jobs with polling:** some lookups take 10 to 30 seconds. Polling is simpler and more robust than websockets for this size.
- **Why a curated exclusion list:** see [ETHICS_AND_LEGAL.md](ETHICS_AND_LEGAL.md).
