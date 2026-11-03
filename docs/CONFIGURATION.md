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
| `RATE_LIMIT_HEAVY` | 20 | Max starts of investigations and EXIF uploads per IP per minute |
| `RATE_LIMIT_GENERAL` | 300 | Max other requests per IP per minute |
| `DB_PATH` | `osint.db` next to `main.py` | SQLite file for cases |
| `HIBP_API_KEY` | empty | Have I Been Pwned breach check for emails |
| `SHODAN_API_KEY` | empty | Shodan host data for IPs |
| `VIRUSTOTAL_API_KEY` | empty | VirusTotal reputation for domains and IPs |
| `ABUSEIPDB_API_KEY` | empty | AbuseIPDB reports for IPs |
| `SEC_USER_AGENT` | `OSINT-Hub/1.0 admin@localhost` | SEC EDGAR asks for a contact in the User-Agent. Use your own, for example `MyOrg admin@example.com`. |

Keys are never sent to the browser. `/api/config` only says whether each one is set.

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
- [ ] You have read [ETHICS_AND_LEGAL.md](ETHICS_AND_LEGAL.md) and decided who may use the instance
