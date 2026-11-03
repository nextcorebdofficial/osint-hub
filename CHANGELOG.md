# Changelog

All notable changes are listed here. Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added (accounts and branding)
- Email + password accounts (`AUTH_MODE=accounts`) with email confirmation and password reset by free providers (Resend, Brevo or SMTP)
- Public home page (English and Bengali), sign-in and sign-up pages; the tools sit behind sign-in
- Per-account private cases, data export and account deletion, daily investigation cap, invite-only or closed registration
- Security hardening: nonce-based CSP, HSTS, same-origin check on writes, request size limits, sign-in lockout, no Host-header links in emails, `security.txt`, `robots.txt`
- NextCore BD branding (`BRAND_NAME`): purple palette, new logo (a magnifier holding a link graph), favicon, `/logo.svg`
- Catalog additions in `extra_tools.json`: directories (IntelTechniques, OSINT.link, Awesome OSINT, Bellingcat toolkit, Start.me) and automated engines (SpiderFoot, Recon-ng, Maltego, WhatsMyName, Maigret), plus SecurityTrails
- New catalog category "Recon & Attack Surface": ProjectDiscovery suite, Amass, Masscan, Nmap, RustScan, theHarvester, Sublist3r, BBOT. Active scanners carry an authorisation warning; the hub itself only does passive lookups
- Safe mode (default with accounts): no lookups about individuals; `/report` abuse page; `admin.py` to block, delete and read reports; 18+ confirmation at sign-up; 30-day default retention; `docs/SAFE_LAUNCH.md`
- Optional SecurityTrails lookup (`SECURITYTRAILS_API_KEY`): subdomains and A-record history for domains

### Fixed
- Sign-up and sign-in were blocked in browsers because `Referrer-Policy: no-referrer` made them send `Origin: null`; the same-origin check now uses `Sec-Fetch-Site`

### Added
- Required purpose for every investigation, with an audit log that stores a keyed hash of the target, never the target or IP (`AUDIT_LOG`)
- Optional retention: `CASE_RETENTION_DAYS` deletes old cases at start
- Legal pages at `/legal/*` (privacy, terms, acceptable use, disclaimer) filled from `OPERATOR_NAME`, `OPERATOR_CONTACT`, `OPERATOR_JURISDICTION`
- Docs: legal compliance guide, abuse and takedown process, code of conduct
- Security headers and a Content-Security-Policy on all pages

### Added (deployment)
- `CASES_ENABLED`: cases are off by default on public serverless instances without a login
- Vercel support: `vercel.json`, in-request investigations, Turso storage, stdout audit lines, forwarded client IP
- Deployment guide in English and Bengali (`docs/DEPLOY_VERCEL.md`)

### Changed
- Dork generator is now `POST /api/toolbox/dorks` so targets do not appear in URLs

## [0.1.0] - 2026-11-03

First public release.

### Added
- Catalog of 1165 tools in 33 categories from the OSINT Framework, with search and filters
- Investigations with automatic target-type detection, background jobs with progress, 15-minute cache
- Lookups for domain, IP, email, username, phone, crypto address, URL and company
- Optional integrations: Have I Been Pwned, Shodan, VirusTotal, AbuseIPDB
- Pivoting from results and an entity graph
- Cases stored in SQLite with notes and Markdown, JSON and HTML export
- Toolbox: 16 encode/decode/hash operations, dork generator, EXIF/GPS reader
- Optional password login, per-IP rate limits, SSRF guard, input validation
- Dark and light theme, English and Bengali labels
- Offline test suite, Dockerfile, docker-compose, GitHub Actions CI, data updater with dead-link check

### Excluded on purpose
- Facial-recognition identification services (FaceCheck, PimEyes, Lenso, FaceSeek)
