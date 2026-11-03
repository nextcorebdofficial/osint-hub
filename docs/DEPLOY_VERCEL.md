# Deploying on Vercel

Bengali version: [DEPLOY_VERCEL.bn.md](DEPLOY_VERCEL.bn.md)

The app runs on Vercel's Python runtime. Vercel is serverless, so a few things work differently from a laptop or VPS.

| Area | On Vercel |
|---|---|
| Investigations | Run inside one request (no background jobs, no progress counter). Limit is capped at 200 sites for username scans. |
| Cases | Stored in **Turso** (free, persistent). Without Turso they go to a temp file that is wiped regularly, and `/api/config` reports `"storage": "sqlite-temp"`. |
| Audit log | Written to Vercel's runtime logs as lines starting with `AUDIT ` (target hash only), because the disk is read-only. |
| Rate limits and cache | Per instance, so they are best effort, not a hard guarantee. |
| Client IP | Taken from `X-Forwarded-For`, which Vercel sets. |

Vercel Hobby is for **non-commercial** use. Client or revenue work needs Pro.

## 1. Put the code on GitHub

```bash
git remote add origin https://github.com/<you>/osint-hub.git
git push -u origin main
```

Use a private repository if you do not want the code public. Vercel can deploy private repos.

## 2. Create a free Turso database (for saved cases)

1. Sign up at <https://turso.tech> and create a database.
2. Copy its URL (`libsql://...turso.io`) and create an auth token.
3. These become `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` below.

The tables are created automatically on first use.

## 3. Import the project in Vercel

1. <https://vercel.com/new> and import the GitHub repository.
2. Framework preset: **Other**. Leave build and output settings empty; `vercel.json` handles it.
3. Before pressing Deploy, open **Environment Variables** and add the values from your local `vercel-env.local.txt` (created for you, git-ignored):

| Variable | Required | Notes |
|---|---|---|
| `APP_PASSWORD` | yes | Login for the whole app |
| `APP_SECRET` | yes | Must be fixed, or logins fail across instances |
| `OPERATOR_NAME`, `OPERATOR_CONTACT`, `OPERATOR_JURISDICTION` | yes, if others use it | Shown on `/legal/*` |
| `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN` | recommended | Persistent cases |
| `CASE_RETENTION_DAYS` | recommended | For example 30 |
| `HIBP_API_KEY`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `SEC_USER_AGENT` | optional | Extra lookups |

4. Deploy. Every later `git push` to `main` deploys automatically.

## 4. Add your domain

Project, **Settings**, **Domains**, add your domain, then set the DNS records Vercel shows (an `A` record for the apex or a `CNAME` for a subdomain). HTTPS is automatic.

## 5. Check it

- `https://your-domain/api/health` returns `{"ok": true, ...}`
- `https://your-domain/legal/privacy` opens without login and shows your operator name
- Log in, run a phone lookup (works without any API key), save it to a case
- `https://your-domain/api/config` shows `"storage": "turso"` after login

## Limits and troubleshooting

- **Slow lookups time out.** The function limit depends on your plan. Username scans over many sites are the slowest; use a lower limit.
- **Logged out at random:** `APP_SECRET` is not set.
- **Cases disappear:** Turso variables are missing, check `/api/config`.
- **Build says bundle too large:** the repo should not include `.venv` (it is in `.vercelignore`).
- Read the audit lines in Vercel: project, **Logs**, search for `AUDIT`.
