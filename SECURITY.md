# Security policy

## Reporting a vulnerability

Please report security problems privately. Use GitHub's **Report a vulnerability** button on the repository's Security tab (private vulnerability reporting). Do not open a public issue for a security bug.

Include: what you found, how to reproduce it, the version or commit, and the impact you expect. You will get an acknowledgement, and fixes are released as soon as practical with credit if you want it.

## What is in scope

- Authentication bypass of the optional login
- SSRF or other ways to make the server reach private networks (the URL lookup has a guard, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md))
- Cross-site scripting through lookup results, reports or saved cases
- Path traversal or arbitrary file access through uploads or exports
- Exposure of API keys or the `.env` file
- Ways to bypass rate limits that cause real abuse

## Out of scope

- Findings that need a deployment without `APP_PASSWORD` (the app tells you to set one)
- Missing HTTPS when you did not put the app behind a TLS proxy
- Results from third-party services being wrong or incomplete
- Denial of service by sending huge numbers of requests from many IPs

## Safe-use reminders for operators

Set `APP_PASSWORD` and a fixed `APP_SECRET`, serve over HTTPS, keep `.env` and `osint.db` out of version control, and read [docs/CONFIGURATION.md](docs/CONFIGURATION.md).
