# OSINT Hub

**Every tool from the [OSINT Framework](https://osintframework.com/) in one searchable place, plus built-in lookups, saved cases and a toolbox, all in a single self-hosted Python web app.**

[বাংলা README](README.bn.md) &middot; [Architecture](docs/ARCHITECTURE.md) &middot; [API reference](docs/API.md) &middot; [Configuration](docs/CONFIGURATION.md) &middot; [Ethics and legal](docs/ETHICS_AND_LEGAL.md) &middot; [Contributing](CONTRIBUTING.md)

---

## What is OSINT?

OSINT stands for **Open Source Intelligence**: finding and analysing information that is publicly available, such as DNS records, domain registrations, public profiles, company registries, blockchain explorers and archived web pages. Security teams, journalists, fraud investigators and researchers use it every day.

The OSINT Framework is a well-known directory of more than a thousand OSINT tools and websites. The problem with a directory is that you still have to open each link, type your target in again and again, and keep your notes somewhere else.

**OSINT Hub fixes that.** You enter one target (a domain, IP, email, username, phone number, URL, crypto address or company). The app detects what it is, runs the lookups it can run for you, shows you the results, lists every relevant framework tool for that target type, and lets you save everything into a case you can export as a report.

## Features

| Area | What you get |
|---|---|
| **Catalog** | 1165 tools in 33 categories from the OSINT Framework. Full-text search, and filters for category, price (free/freemium/paid), has-API, local-install and Google-dork tools. |
| **Investigate** | One input box, automatic target-type detection, background jobs with live progress, 15-minute result cache. |
| **Pivoting** | Every IP, domain and email inside a result is clickable: investigate it next. An entity graph shows what a result connects to. |
| **Cases** | Save results into cases (SQLite), add notes, export as Markdown, JSON or printable HTML (save as PDF). |
| **Toolbox** | 16 encode/decode/hash operations, hash identifier, Google dork generator, EXIF and GPS reader for photos you upload. |
| **Safety** | Optional password login, per-IP rate limits, SSRF guard on URL fetching, input validation. |
| **Usability** | Dark and light theme, English and Bengali labels, works on a phone. |
| **Operations** | Tests, Dockerfile, docker-compose, GitHub Actions CI, data updater with dead-link checker. |

### Built-in lookups

| Target | What the app looks up for you | Needs a key? |
|---|---|---|
| **Domain** | DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA), RDAP/WHOIS (registrar, dates, status), subdomains from certificate transparency (crt.sh), Wayback Machine first/last snapshot | VirusTotal part only |
| **IP address** | Geolocation, ASN and network owner, RDAP allocation, reverse DNS | Shodan, AbuseIPDB, VirusTotal parts only |
| **Email** | MX and SPF of the domain, Gravatar presence, data-breach names | Breaches need Have I Been Pwned |
| **Username** | Checks whether the name exists on up to 700 public sites (WhatsMyName dataset) | No |
| **Phone number** | Validity, country, line type, original carrier, time zones. Offline, parses the number only. | No |
| **Crypto address** | Bitcoin (Blockstream) or Ethereum (Blockscout): balance, totals, transaction counts, contract flag, ENS name | No |
| **URL** | Redirect chain, selected response headers, page title, Wayback snapshots. Public hosts only. | No |
| **Company** | Legal entities from GLEIF, matches in SEC EDGAR, links to registries | No |

Anything marked "needs a key" shows a clear "set X to enable" note until you add your own key. Nothing is hidden or faked.

## Quick start

You need Python 3.10 or newer.

```bash
git clone https://github.com/nextcorebdofficial/osint-hub.git
cd osint-hub
python -m venv .venv
.venv\Scripts\activate          # Windows; on Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

Open <http://127.0.0.1:8000>. Interactive API documentation is at <http://127.0.0.1:8000/docs>.

### With Docker

```bash
cp .env.example .env     # edit it, at least set APP_PASSWORD
docker compose up --build
```

Cases are stored in a Docker volume called `osint-data`, so they survive restarts.

## Using it

1. Type a target in the top box, for example `example.com`, `8.8.8.8`, `someone@example.com`, `octocat`, `+14155552671`, `https://example.com`, a Bitcoin or Ethereum address, or a company name.
2. Leave the type on **auto-detect**, or force one (useful for company names).
3. Press **Investigate**. Slow lookups (domains, username sweeps) show progress.
4. Read the result. Click any chip or graph node to pivot to that value.
5. Pick a case and press **Save to case**. Create cases in the **Cases** tab.
6. In **Cases**, open a case, add notes, and export a report.
7. Use **Catalog** to browse all tools, and **Toolbox** for encoders, dorks and EXIF.

Phone numbers should include the country code (`+880...`). Without it, type the two-letter region (for example `BD`) in the small box next to the type selector.

## Project layout

```
main.py            FastAPI app: routes, jobs, cache, login, rate limit, catalog
lookups.py         All lookups and API-key integrations
extras.py          Encoders, hash identifier, dork generator, EXIF reader
db.py              SQLite storage for cases and items
report.py          Markdown and HTML report export
data.json          OSINT Framework tree (refresh with update_data.py)
update_data.py     Refresh data.json, optional dead-link check
templates/         index.html (the whole UI) and login.html
test_app.py        Offline tests (no network needed)
docs/              Architecture, API, configuration, ethics
Dockerfile, docker-compose.yml, .env.example
```

More detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Configuration

Everything is optional and set through environment variables or a `.env` file. The important ones:

| Variable | Purpose |
|---|---|
| `APP_PASSWORD` | Require a password to use the app. **Set this before exposing the app to a network.** |
| `APP_SECRET` | Random string used to sign the login cookie. |
| `HIBP_API_KEY`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | Turn on the keyed lookups. |
| `RATE_LIMIT_HEAVY`, `RATE_LIMIT_GENERAL` | Requests per IP per minute. |
| `DB_PATH` | Where cases are stored. |

Full list and deployment notes: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Keeping data fresh

```bash
python update_data.py                 # download the latest framework data
python update_data.py --check-links   # also list dead links in dead_links.json
python -m pytest -q test_app.py       # run the offline tests
```

## Responsible use

OSINT only uses public information, but public does not mean harmless. People can be harassed, stalked or defrauded with it. Please read [docs/ETHICS_AND_LEGAL.md](docs/ETHICS_AND_LEGAL.md) before you use or deploy this project.

The app asks for a purpose on every investigation, keeps an audit log without storing targets, can auto-delete old cases (`CASE_RETENTION_DAYS`), and serves policy pages at `/legal/*`. If you host it for others, set `OPERATOR_NAME`, `OPERATOR_CONTACT` and `OPERATOR_JURISDICTION`, and read [docs/LEGAL_COMPLIANCE_GUIDE.md](docs/LEGAL_COMPLIANCE_GUIDE.md) and [docs/ABUSE_AND_TAKEDOWN.md](docs/ABUSE_AND_TAKEDOWN.md).

In short, and by design:

- **No facial-recognition search engines.** FaceCheck, PimEyes, Lenso and FaceSeek are removed from the dataset and from the updater, because they identify strangers from a photo without consent.
- **The phone lookup parses the number only.** It does not tell you who owns it.
- **URL fetching refuses private addresses**, so a public deployment cannot be used to probe your internal network.
- **Put a password on any deployment that other people can reach.**

Use it lawfully, and only on targets you are entitled to investigate.

## Deploying

Docker, a VPS or **Vercel** all work. Step by step for Vercel with your own domain: [docs/DEPLOY_VERCEL.md](docs/DEPLOY_VERCEL.md) ([বাংলা](docs/DEPLOY_VERCEL.bn.md)).

## Known limitations

Honest list, so nobody is surprised:

- Jobs and the result cache live in memory and are lost on restart. Cases are persistent.
- Rate limits are per process. Behind several workers or servers they are not shared.
- There is one shared password, not separate user accounts.
- The username sweep can give false positives and false negatives; sites change their pages. Treat hits as leads to verify.
- crt.sh can be slow or time out; domain lookups may take up to about 30 seconds.
- The URL fetcher checks addresses before connecting but cannot fully rule out DNS rebinding.
- Most of the 1165 catalog entries are links to external tools, not features running inside this app.

## Roadmap

Ideas for the next steps. Contributions are welcome (see [CONTRIBUTING.md](CONTRIBUTING.md)).

- Separate user accounts and roles
- PostgreSQL option, and Redis for jobs and cache so it can run on several workers
- More integrations: Censys, SecurityTrails, Hunter, GitHub, Reddit
- Persistent entity graph across cases
- Scheduled monitoring and alerts for a target
- Native PDF export
- More languages
- A plugin system so anyone can add a lookup in one file

## Credits and licences

- **OSINT Framework** by Justin Nordine, <https://osintframework.com/>, source at <https://github.com/lockfale/OSINT-Framework>. The tool directory in `data.json` comes from there. All credit for curating it belongs to the OSINT Framework authors and contributors.
- **WhatsMyName** by Micah "WebBreacher" Hoffman and contributors, <https://github.com/WebBreacher/WhatsMyName>. The username site list is downloaded at runtime and is not redistributed in this repository.
- Public services used by the lookups: dns.google, RDAP (rdap.org), crt.sh, ipwho.is, Wayback Machine / Internet Archive, Blockstream, Blockscout, GLEIF, SEC EDGAR, Gravatar. Please respect their terms and rate limits.

This project's own code is released under the [MIT License](LICENSE). See [NOTICE](NOTICE) for third-party details.
