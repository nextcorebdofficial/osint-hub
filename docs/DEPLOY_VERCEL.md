# Deploying on Vercel, free

Bengali version: [DEPLOY_VERCEL.bn.md](DEPLOY_VERCEL.bn.md)

This setup costs nothing and handles thousands of users:

| Part | Service | Free tier (check current limits) |
|---|---|---|
| App | Vercel Hobby | Scales automatically, custom domain and HTTPS |
| Accounts and cases | Turso | Several GB of storage and hundreds of millions of reads per month |
| Confirmation and reset emails | Resend (3,000/month) or Brevo (300/day) or any SMTP | Free |

Vercel is serverless, so a few things differ from a laptop or VPS:

| Area | On Vercel |
|---|---|
| Investigations | Run inside one request (no background jobs). Username scans are capped at 200 sites. |
| Accounts, cases | Stored in Turso. Without it, sign-up is switched off (the home page still works). |
| Audit log | Goes to Vercel's runtime logs as lines starting with `AUDIT ` (target hash only). |
| Rate limits | Per instance and best effort. Per-account daily limits are exact (stored in Turso). |
| Client IP | From `X-Forwarded-For`, which Vercel sets. |

Vercel Hobby is meant for **non-commercial** use. A free community service is fine; if you start charging, move to Pro.

## 1. Code on GitHub

```bash
git remote add origin https://github.com/<you>/osint-hub.git
git push -u origin main
```

## 2. Turso (database)

1. Sign up at <https://turso.tech>, create a database.
2. Copy its URL (`libsql://...turso.io`) and create an auth token.

Tables are created and migrated automatically.

## 3. Email sender

Pick one:

- **Brevo** (<https://brevo.com>): verify one sender address (even a Gmail address), create an API key. `MAIL_PROVIDER=brevo`.
- **Resend** (<https://resend.com>): verify your domain, create an API key. `MAIL_PROVIDER=resend`.
- **SMTP**: any server, for example Gmail with an app password. `MAIL_PROVIDER=smtp` plus `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`.

`MAIL_FROM` looks like `NextCore BD <no-reply@yourdomain.org>` and must be an address the provider has verified.

## 4. Vercel project

1. <https://vercel.com/new>, import the repository, Framework **Other**.
2. Add these Environment Variables (Production). Your local `vercel-env.local.txt` has `APP_SECRET` ready.

| Variable | Value |
|---|---|
| `AUTH_MODE` | `accounts` |
| `APP_SECRET` | long random value, must stay fixed |
| `PUBLIC_URL` | your final address, for example `https://osint.example.org` |
| `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN` | from step 2 |
| `MAIL_PROVIDER`, `MAIL_FROM`, `MAIL_API_KEY` | from step 3 |
| `OPERATOR_CONTACT`, `OPERATOR_JURISDICTION` | contact email and country, shown on the legal pages |
| `CASE_RETENTION_DAYS` | for example `30` (optional) |
| `DAILY_INVESTIGATIONS` | per account per day, default 100 |
| `REGISTRATION` | `open`, `invite` or `closed` |
| API keys (optional) | `HIBP_API_KEY`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` |

3. Deploy. Later pushes to `main` redeploy when the repository is connected.
4. **Settings, Deployment Protection**: turn off Vercel Authentication, otherwise visitors must sign in to Vercel.

## 5. Domain

**Settings, Domains**, add the domain and set the DNS records Vercel shows. HTTPS is automatic. Update `PUBLIC_URL` to match and redeploy.

## 6. Check it

- `/` shows the home page, `/legal/privacy` opens without login
- Sign up, open the email link, sign in, run a phone lookup
- `/api/config` after sign-in shows `"storage": "turso"`
- Forgot password sends a link and the new password works

## Running at scale

- Add a rule in Vercel **Firewall** to rate limit `/login`, `/register`, `/forgot` and `/api/*` across all instances.
- Public lookup services (RDAP, DNS over HTTPS) have their own limits. Add the optional API keys if you grow.
- To block an abusive account, delete its row in Turso or set `REGISTRATION=invite`.

## Troubleshooting

- **Sign-up says unavailable:** one of `APP_SECRET`, `PUBLIC_URL`, Turso or the email variables is missing. The reason is in Vercel Logs as `ACCOUNTS UNAVAILABLE`.
- **No email arrives:** check spam, then that `MAIL_FROM` is verified at the provider.
- **Logged out at random:** `APP_SECRET` is not set.
- **Audit lines:** project, **Logs**, search `AUDIT`.
