<!-- TEMPLATE: a starting point, not legal advice. The operator must fill in the placeholders and have a lawyer review it before offering the service to the public. See docs/LEGAL_COMPLIANCE_GUIDE.md. -->

# Privacy Policy

**Last updated:** 2026-11-03
**Operator of this instance:** [OPERATOR_NAME]
**Contact for privacy questions:** [OPERATOR_CONTACT]
**Governing jurisdiction:** [JURISDICTION]

OSINT Hub is open-source software. This policy explains what happens to data on **this instance**, which is run by the operator named above, not by the authors of the software. The authors of the software do not receive any data from instances they do not run.

## The short version

- We do **not** use analytics, advertising, tracking pixels or third-party scripts.
- We do **not** sell or share your data for marketing.
- The only cookie is a login cookie, if the operator turned login on.
- What you type as a target is sent to the public services listed below so they can answer. It is **not saved** unless you save it into a case.
- We keep a small **audit log** that does not contain the targets or your IP address.
- Saved cases can be deleted by you at any time, and may be deleted automatically after a set number of days.

## 1. What data is processed

### a) Targets you enter
A target is something you type to investigate, such as a domain, IP address, email address, username, phone number, URL, crypto address or company name. Some of these can relate to a real person.

- It is sent to the public services listed in section 3 to get answers.
- Results are kept in the server's memory for about 15 minutes (a cache and the job list) and then forgotten. They are also forgotten if the server restarts.
- A target and its result are written to disk **only** if you press "Save to case".

### b) Saved cases
When you save a result, the target, the result, the time and any note you type are stored in the operator's database. You can delete an item or a whole case in the Cases tab at any time. If the operator has set a retention period (shown at the bottom of every page), old cases are deleted automatically.

### c) Audit log
For every investigation, one line is appended to a log file: the time, the target **type** (for example "domain"), the **purpose** you chose, and a keyed hash of the target. The hash cannot be turned back into the target without guessing it and knowing the operator's secret key. The log does **not** contain the target itself, your IP address, your name or your results. It exists so the operator can see how the tool is used and investigate abuse, for example repeated use against one target.

### d) Login cookie
If the operator enabled a password, a cookie named `osint_session` is set when you sign in. It is strictly necessary for the login to work, is marked HttpOnly, lasts up to 7 days, and is marked Secure when the site is served over HTTPS. It contains no personal data.

### e) Browser storage
Your browser stores a few preferences on your own device: theme, language, the purpose you last chose, and that you accepted the notice. They are not sent to the server and you can clear them in your browser.

### f) Technical data
To limit abuse, the server counts requests per IP address in memory for up to one minute and then discards the count. The operator's web server or reverse proxy may keep ordinary access logs (IP address, time, requested page). Targets are sent in the body of requests, not in the address, so they do not appear in those logs. The operator is responsible for how long their own logs are kept.

### g) Uploaded images
If you use the EXIF reader, the image is read in memory and discarded. It is not written to disk.

## 2. Why the data is processed

- To provide the lookups you ask for.
- To let you keep your own notes and reports (saved cases).
- To keep the service secure and prevent abuse (rate limits, audit log).

The operator decides the legal basis that applies to them (for example legitimate interests or your consent under data-protection law) and should state it here: [LEGAL BASIS, if required in your jurisdiction].

## 3. Who receives the targets you enter

Looking something up means asking another service. The target (or part of it) is sent as follows. Nothing is sent to anyone else.

| You investigate | Services contacted | What they receive |
|---|---|---|
| Domain | dns.google (Google Public DNS), rdap.org and the registry it redirects to, crt.sh, archive.org (Wayback Machine), VirusTotal (only if a key is set) | the domain |
| IP address | ipwho.is, rdap.org and the registry, dns.google, Shodan / AbuseIPDB / VirusTotal (only if keys are set) | the IP address |
| Email address | dns.google, Gravatar, Have I Been Pwned (only if a key is set) | the domain part (dns.google); an MD5 hash of the address (Gravatar); the full address (Have I Been Pwned) |
| Username | up to about 700 public websites, one request each | the username, inside the page address |
| Phone number | nobody (processed on the server only) | nothing |
| Crypto address | Blockstream (Bitcoin) or Blockscout (Ethereum) | the address |
| URL | the website at that URL, archive.org | the request for the page, and the URL |
| Company name | GLEIF | the name |
| Dork generator, encoders, EXIF | nobody | nothing |

Those services have their own privacy policies and may log requests. The operator's server IP address is what they see, not yours. The list of sites for username checks is downloaded from GitHub (raw.githubusercontent.com) and contains no target data.

Links in the tool catalog open other websites in your browser; from then on, that site's policy applies.

## 4. How long data is kept

| Data | Kept for |
|---|---|
| Results in memory (cache, job list) | about 15 minutes, or until restart |
| Saved cases | until you delete them, or automatically after the retention period if the operator set one |
| Audit log | until the operator rotates or deletes it; the operator should keep it no longer than needed to deal with abuse, for example [AUDIT LOG RETENTION] |
| Login cookie | up to 7 days |
| Per-IP request counts | up to 1 minute, memory only |

## 5. Your rights

Depending on where you live, you may have the right to know what is held about you, to have it corrected or deleted, to object to or restrict processing, and to complain to a data-protection authority. You can delete your own saved cases yourself at any time. For anything else, write to [OPERATOR_CONTACT].

### If you are the subject of a lookup
If you believe someone used this instance to look you up, and you want information removed or want to report misuse, contact [OPERATOR_CONTACT]. Because targets are not stored unless saved to a case, and the audit log holds only a keyed hash, the operator may not be able to find a lookup from a name alone, but will do what is reasonably possible, for example deleting a saved case, blocking an account, or reviewing for abuse. Please also contact the original services (for example the website or registry) if you want the underlying public information changed; this tool only reads what they publish.

## 6. Security

The operator is expected to use HTTPS, a strong password, and keep the server updated. The software adds rate limits, input checks, a guard against fetching private network addresses, and security headers. No system is perfectly secure; if there is a breach affecting you, the operator will notify you as the law requires.

## 7. Children

This service is not for people under 18 and is not directed at children. Do not use it to look up children.

## 8. International transfers

The public services listed above are run by companies in many countries, so a target you enter may be processed outside your country.

## 9. Changes

The operator may update this policy. The date at the top shows the latest version.

## 10. Contact

[OPERATOR_NAME], [OPERATOR_CONTACT]
