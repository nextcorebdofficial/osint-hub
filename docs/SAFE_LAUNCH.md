# Safe launch checklist

This is a practical list for running a public instance with the least legal exposure. It is **not legal advice**
and no software can remove legal duties, but these choices keep the risk small without paying for a consultation.

## Already built in (nothing to do)

- **Safe mode** (default for account instances): only domains, IP addresses, URLs, crypto addresses and companies.
  No lookups about individuals, no face recognition, no phone-owner lookups, no leak databases, no monitoring of people.
- **No tracking**: no analytics, ads or third-party scripts; one essential sign-in cookie, so no cookie banner.
- **Minimal data**: email and a password hash; saved cases deleted after 30 days; the audit log holds only a keyed hash.
- **Accountability**: every investigation needs a stated purpose; accounts need a confirmed email and the 18+ and terms checkbox.
- **Abuse handling**: public `/report` page, reports emailed to `OPERATOR_CONTACT`, `python admin.py block <email>`.
- **Your rights**: users can download all their data and delete their account in the app.
- **Hosting terms**: passive lookups only; nothing scans third parties from the server.

## You do

1. Keep `OPERATOR_NAME`, `OPERATOR_CONTACT` (an inbox you read) and `OPERATOR_JURISDICTION` filled in.
2. Read the inbox. Answer a report within a few days; block or delete the account if it is abuse (`python admin.py reports`).
3. Do not switch `SAFE_MODE` off on the public instance, and do not add tools that identify people.
4. Keep Vercel on a plan that matches your use (Hobby is non-commercial).
5. Once a month: `python update_github_tools.py` to refresh the catalog, review the diff, push.

## Honest limits

The legal texts are templates written in plain language to match what the software does. A local lawyer could still
find a local rule they do not cover. If your service grows, a one-hour review is the cheapest insurance. Until then the
design above keeps what you hold and what you can be asked about to a minimum.
