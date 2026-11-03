# Ethics and legal notes

This is not legal advice. Laws differ by country; ask a lawyer if you are unsure.

## Public does not mean harmless

OSINT works with information anyone can reach. But combining scattered public facts can expose where a person lives, works, or spends time, and has been used for stalking, harassment, doxxing, fraud and social engineering. The project is built for defence, research, journalism and verification, not for targeting private individuals.

## Design choices this project makes on purpose

1. **No facial-recognition search engines.** Services that take a photo and return who the person is (FaceCheck, PimEyes, Lenso, FaceSeek) are removed from the dataset and filtered out by `update_data.py`. They identify strangers from their face without consent, and in several jurisdictions processing face data this way is illegal (for example under the EU GDPR and Illinois BIPA). If you fork the project, please keep this.
2. **The phone lookup only parses the number.** It tells you the country, line type and original carrier. It does not look up the owner.
3. **No scraping of personal data.** Lookups use public APIs and public registries, within their terms.
4. **URL fetching refuses private addresses**, so a hosted instance cannot be used to reach internal networks.
5. **Honest results.** Missing keys, errors and unknowns are shown as such, never filled in.

## Principles for users

- Investigate only what you are entitled to: your own assets, your employer's with permission, a client who has authorised you in writing, or genuinely public-interest research.
- Collect the minimum you need. Do not keep personal data longer than the purpose requires; delete cases when done.
- Verify before you act. A username match is a lead, not proof of identity.
- Do not use results to contact, pressure, threaten or expose private individuals.
- Respect the terms of service and rate limits of the services this tool queries.

## Running a public instance

If you host this for other people, you are responsible for how it is used.

- Require a login (`APP_PASSWORD`) and decide who gets access.
- Keep the rate limits on.
- Consider a terms-of-use page and a way for people to report abuse.
- Know the data-protection law that applies to you (for example GDPR, UK GDPR, CCPA). Saved cases can contain personal data.

## Third-party data and terms

- The tool list comes from the OSINT Framework (MIT licence).
- The username site list comes from WhatsMyName, downloaded at runtime and not redistributed here.
- External services (DNS, RDAP, crt.sh, Wayback Machine, Blockstream, Blockscout, GLEIF, SEC EDGAR, ipwho.is, Gravatar, and the keyed ones) have their own terms and limits.

## Reporting misuse or a problem

See [SECURITY.md](../SECURITY.md) for security issues. For misuse concerns about a project feature, open an issue.
