# Legal and compliance guide for the author and for operators

> **Read this first.** This guide is practical information, not legal advice, and I (the assistant that helped write it) am not a lawyer. Laws differ by country and change over time. Nothing here can make anyone "immune" from legal trouble. What it can do is help you **reduce risk, show good faith, and know when to ask a lawyer.** If you plan to offer this to the public, have a qualified lawyer in your country review the documents in `docs/legal/` first.

## 1. Two different roles

The most important idea in this guide is that there are two different things you might be doing.

| Role | What it means | Typical risk |
|---|---|---|
| **Software author / publisher** | You publish source code on GitHub under the MIT Licence. Other people download and run it themselves. | Lower. You are not collecting or processing anyone's data. You still want clear warnings, a licence with no-warranty terms, and a policy against abuse. |
| **Operator of an instance** | You run the app on a server, and other people use it. Targets pass through your server, cases are stored on it. | Higher. You may be responsible for how the service is used, for personal data stored on it, and for responding to complaints and legal requests. |

**Recommendation:** publish the **software** freely. Do **not** run an open, public instance until you have done section 5. Running a private instance for yourself or a vetted team is far lower risk.

## 2. What the project already does to protect people (and you)

Built into the software:

- **No face-recognition search.** Services that identify strangers from a photo are removed from the dataset and from the updater. These are the services most associated with stalking and with data-protection enforcement.
- **No ownership look-up for phone numbers.** The phone lookup only parses the number.
- **No scanning, logging in, brute force, exploitation or scraping behind logins.** The tool reads public pages and public APIs. This matters for computer-misuse laws, which usually focus on *unauthorised access*.
- **Purpose required** for every investigation, chosen from five lawful purposes.
- **Consent notice** before first use, and a required tick-box on the login page.
- **Audit log** with time, type, purpose and a keyed hash of the target, but never the target or IP address, so the log helps with abuse without becoming a list of people.
- **Retention limit** (`CASE_RETENTION_DAYS`) to delete old saved cases automatically.
- **No personal data in URLs** (targets are sent in request bodies, including for the dork generator), so they do not land in access logs.
- **Private-address guard** on URL fetching, so a hosted instance cannot be used to probe an internal network.
- **Password login, rate limits, input validation and security headers.**
- **No analytics, ads, tracking or third-party scripts.**
- **Legal pages** served at `/legal/terms`, `/legal/privacy`, `/legal/acceptable-use`, `/legal/disclaimer`, with placeholders for your name, contact and jurisdiction that the page warns about until you fill them in.

In the repository:

- MIT Licence (no warranty, no liability), `NOTICE` crediting data sources, clear "not affiliated" statements.
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, `docs/ETHICS_AND_LEGAL.md`, `docs/ABUSE_AND_TAKEDOWN.md`.
- A pull-request checklist that rejects face identification and personal-data scraping.

## 3. What the software deliberately does not do

State this clearly whenever anyone asks. It is the main reason the project is defensible.

- It does not send a single packet that tests a system's security. No port scans, no vulnerability checks, no login attempts.
- It does not keep a database of people. Targets live in memory for about 15 minutes unless a user saves them into a case.
- It does not identify a person from a photograph.
- It does not tell you who owns a phone number or email address.
- It does not bypass paywalls, logins, robots rules or rate limits of other services.

## 4. Choosing how to run it

| Mode | Who uses it | What to do | Risk |
|---|---|---|---|
| **Personal** | You, on your own computer | Nothing special; keep the default settings | Lowest |
| **Team** | A small group you know | `APP_PASSWORD`, `APP_SECRET`, HTTPS, `OPERATOR_*` filled in, `CASE_RETENTION_DAYS=30`, written rules for the team | Low to medium |
| **Public** | Anyone | Everything in section 5, plus a lawyer | Highest |

## 5. Checklist before offering a public instance

Do not skip these.

**Legal**
- [ ] A lawyer in your country has reviewed `docs/legal/*` and this guide, and told you whether you need a company or other legal entity to separate your personal assets from the service.
- [ ] You know which laws apply: computer misuse and cybercrime laws, data-protection and privacy laws (for example the EU/UK GDPR if you have users or targets there, and the data-protection law of your own country), laws on harassment and stalking, and consumer-protection rules for your terms.
- [ ] You have decided whether you must register with a data-protection authority, appoint a representative or contact person, or do a risk assessment (DPIA). Ask your lawyer.
- [ ] `OPERATOR_NAME`, `OPERATOR_CONTACT` and `OPERATOR_JURISDICTION` are filled in and the legal pages show no warning.
- [ ] The placeholders `[LEGAL BASIS...]` and `[AUDIT LOG RETENTION]` in the Privacy Policy are replaced.

**Operations**
- [ ] A real mailbox for abuse and privacy requests that you read, with a promise you can keep about reply time.
- [ ] The process in `docs/ABUSE_AND_TAKEDOWN.md` is something you can actually follow.
- [ ] HTTPS, a strong `APP_PASSWORD`, a fixed `APP_SECRET`, server kept updated, backups encrypted.
- [ ] Retention set (`CASE_RETENTION_DAYS`), and a calendar reminder to rotate or delete `audit.log`.
- [ ] You keep a short record of abuse reports and what you did.

**Access control**
- [ ] Consider **not** making it open to everyone. Invite-only or approval-based access is much safer than public sign-up.
- [ ] Consider turning off the username sweep on a public instance (it contacts hundreds of sites per search and is the feature most easily misused against individuals).
- [ ] Add a terms-acceptance step you can prove if needed (the login page already requires a tick-box).

## 6. General legal pointers (verify locally)

These are broad themes, not statements of current law in any country.

- **Computer misuse / cybercrime laws** typically punish *unauthorised access*, interfering with systems, and sometimes making or sharing hacking tools. Reading public pages and public APIs is generally different from accessing a system without permission, but rules vary, and automated high-volume requests can breach a website's terms or, in some places, the law. This is why the project avoids scanning and logging in. Keep it that way.
- **Data-protection laws** (for example GDPR) can apply even to public information when it relates to an identifiable person. Operators who store such data may need a lawful basis, a privacy notice, deletion on request, security and data minimisation. The audit-log design and retention setting exist for this reason.
- **Stalking and harassment laws** can apply to using search results to follow or pressure someone. The Acceptable Use Policy forbids this, and the purpose requirement and abuse process give you a way to act.
- **Bangladesh:** laws on cyber security, digital communications and data protection have changed in recent years (for example the Cyber Security Act 2023, which replaced the Digital Security Act 2018, and ongoing data-protection proposals). I cannot confirm their current text or status as of today, so please ask a Bangladeshi lawyer which provisions apply to hosting a lookup tool, storing personal data, and handling complaints. Other countries' laws may also apply to your users and your targets.
- **Intermediary and platform rules:** if you host user-driven content or processing, some countries give limited protection when you act quickly on notices. A lawyer can tell you what applies.
- **Law-enforcement requests:** do not hand over data informally. Ask for the request in writing, check it is genuine and lawful, and give only what you hold (which, by design, is little). See `docs/ABUSE_AND_TAKEDOWN.md`.

## 7. If something goes wrong

1. **Stop the harm:** suspend the user or the instance if needed.
2. **Preserve records:** keep the audit log and your notes; do not delete evidence while a request or investigation is open.
3. **Get advice:** contact your lawyer before replying to a legal demand.
4. **Tell people as the law requires:** for example, a personal-data breach may have a notification duty and a deadline.
5. **Fix and document:** close the hole, write down what you changed.

## 8. Keeping the author side safe

- Keep the face-identification and personal-data-scraping ban in the contribution rules and review pull requests for it.
- Do not add features that scan, log in or exploit without a very careful legal review.
- Keep the README and docs honest about limits; do not promise accuracy or legality you cannot guarantee.
- Do not commit real data, keys or personal information, and do not post real people's results in issues or screenshots.
- Respond to abuse reports and removal requests about the **project** (for example a bad listing in the catalog) politely and quickly.
- Stay current: laws change, and so do the terms of the third-party services the tool uses.
