# Changelog

All notable changes are listed here. Format based on [Keep a Changelog](https://keepachangelog.com/).

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
