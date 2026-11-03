# Configuration and deployment

Settings come from environment variables. For convenience the app also reads a `.env` file next to `main.py` (real environment variables win). Start from the template:

```bash
cp .env.example .env
```

`.env` is in `.gitignore`. Never commit it.

## Variables

| Variable | Default | What it does |
|---|---|---|
| `APP_PASSWORD` | empty (no login) | Turns on the login page. Strongly recommended for anything other than your own laptop. |
| `APP_SECRET` | random per start | Signs the login cookie. Set a fixed long random value, otherwise everyone is logged out on every restart. Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`. |
| `AUTH_MODE` | empty | `accounts` turns on the public home page, email + password sign-up and per-user cases. Without it the app uses `APP_PASSWORD` or no login. |
| `REGISTRATION` | `open` | `open`, `invite` (only `ALLOWED_EMAILS` and `ALLOWED_EMAIL_DOMAINS`, comma separated) or `closed`. |
| `DAILY_INVESTIGATIONS` | 100 | Investigations per account per day. `0` removes the cap. |
| `PUBLIC_URL` | empty | The site's public address, for example `https://osint.example.org`. Required on Vercel: email links are built from it, never from the Host header. |
| `MAIL_PROVIDER`, `MAIL_FROM`, `MAIL_API_KEY` | empty | Email for confirmation and reset links. Provider is `resend`, `brevo` or `smtp` (then use `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`). Accounts need this unless `ALLOW_UNVERIFIED=1` (self-hosting only, skips email confirmation). |
| `BRAND_NAME` | `NextCore BD` | Name in the header, home page, emails and legal pages. |
| `SAFE_MODE` | on with `AUTH_MODE=accounts` | `1`/`0`. On: only domains, IPs, URLs, crypto addresses and companies can be investigated (no usernames, emails or phone numbers). |
| `OPERATOR_NAME`, `OPERATOR_CONTACT`, `OPERATOR_JURISDICTION` | empty | Who runs this instance. Filled into the `/legal/*` pages. Until all three are set, those pages show a warning. Required if other people use your instance. |
| `CASE_RETENTION_DAYS` | 0 (keep forever) | Delete saved cases and items older than this many days, at every start. 30 is a good value for shared instances. |
| `AUDIT_LOG` | `audit.log` next to `main.py` | One JSON line per investigation: time, target type, purpose and a keyed hash of the target. Never the target or IP. Set to empty to turn it off. |
| `RATE_LIMIT_HEAVY` | 20 | Max starts of investigations and EXIF uploads per IP per minute |
| `RATE_LIMIT_GENERAL` | 300 | Max other requests per IP per minute |
| `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN` | empty | Store cases in Turso (libSQL) instead of a file. Needed for persistent cases on Vercel. See [DEPLOY_VERCEL.md](DEPLOY_VERCEL.md). |
| `CASES_ENABLED` | auto | `1` or `0`. Saved cases have no per-user separation, so by default they are **off** on Vercel when `APP_PASSWORD` is not set (everyone would see everyone's cases). Set `1` to force them on. |
| `SERVERLESS` | empty | Set to `1` to run investigations inside one request (set automatically on Vercel). |
| `DB_PATH` | `osint.db` next to `main.py` | SQLite file for cases |
| `HIBP_API_KEY` | empty | Have I Been Pwned breach check for emails |
| `SHODAN_API_KEY` | empty | Shodan host data for IPs |
| `VIRUSTOTAL_API_KEY` | empty | VirusTotal reputation for domains and IPs |
| `ABUSEIPDB_API_KEY` | empty | AbuseIPDB reports for IPs |
| `SECURITYTRAILS_API_KEY` | empty | SecurityTrails subdomains and A-record history for domains |
| `SEC_USER_AGENT` | `OSINT-Hub/1.0 admin@localhost` | SEC EDGAR asks for a contact in the User-Agent. Use your own, for example `MyOrg admin@example.com`. |

Keys are never sent to the browser. `/api/config` only says whether each one is set.

Vercel users: see [DEPLOY_VERCEL.md](DEPLOY_VERCEL.md).

## Getting API keys

All of these have a free tier or free application process at the time of writing; check each site for current terms.

- Have I Been Pwned: <https://haveibeenpwned.com/API/Key> (paid)
- Shodan: <https://account.shodan.io/>
- VirusTotal: <https://www.virustotal.com/gui/my-apikey>
- AbuseIPDB: <https://www.abuseipdb.com/account/api>

## Running in production

Do not use `--reload` in production. A reasonable setup:

```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips="127.0.0.1"
```

Put a reverse proxy in front for HTTPS (Caddy, nginx or Traefik). Notes:

- **`--proxy-headers`** lets the app see the real client IP from `X-Forwarded-For`; without it every visitor looks like the proxy and shares one rate-limit bucket. Only trust headers from your own proxy (`--forwarded-allow-ips`).
- **HTTPS** also makes the login cookie `Secure`.
- **Single process:** jobs, cache and rate limits live in memory, so run one worker. Running several works but each has its own memory.
- **Backups:** copy the SQLite file (`DB_PATH`). With Docker, back up the `osint-data` volume.

### Docker

```bash
cp .env.example .env
docker compose up -d --build
```

The container listens on port 8000 and stores cases at `/data/osint.db` in a named volume.

### Caddy example

```
osint.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

## Security checklist before going public

- [ ] `APP_PASSWORD` set to a long, unique password
- [ ] `APP_SECRET` set to a fixed random value
- [ ] Served over HTTPS
- [ ] Running behind a proxy with `--proxy-headers`
- [ ] `.env` and `osint.db` are not in version control or a public web root
- [ ] `OPERATOR_NAME`, `OPERATOR_CONTACT` and `OPERATOR_JURISDICTION` set so the legal pages are complete
- [ ] `CASE_RETENTION_DAYS` set (for example 30) if the instance is shared
- [ ] You have read [LEGAL_COMPLIANCE_GUIDE.md](LEGAL_COMPLIANCE_GUIDE.md) and [ABUSE_AND_TAKEDOWN.md](ABUSE_AND_TAKEDOWN.md)
- [ ] You have read [ETHICS_AND_LEGAL.md](ETHICS_AND_LEGAL.md) and decided who may use the instance
