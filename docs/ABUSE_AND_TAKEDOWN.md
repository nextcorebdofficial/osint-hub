# Abuse reports, removal requests and legal requests

A practical process for the operator of an instance. Adapt it to your situation and your lawyer's advice. Not legal advice.

## 1. Where reports come from

- A person who thinks the tool was used against them.
- A person or organisation who saw misuse.
- A website or service owner complaining about requests from your server.
- The authorities.
- A user or reviewer who notices something wrong in the software or catalog.

Publish one contact address (`OPERATOR_CONTACT`) and monitor it. Aim to acknowledge within **2 working days** and to resolve or explain within **30 days**; change these numbers only if you will really keep to them.

## 2. Triage

| Type | First action | Target time |
|---|---|---|
| Threat to someone's safety (stalking, threats, a minor involved) | Suspend the account or instance now, then investigate | Same day |
| Misuse of the tool by a user | Review the audit log (type, purpose, repeated hashes), contact or block the user | 2 working days |
| Request from a person to delete their data | Verify who they are, delete saved cases that relate to them, confirm in writing | Within the time your law sets (often 30 days) |
| Complaint from a third-party service | Check rate limits, reduce scope (for example turn off the username sweep), reply | 5 working days |
| Legal request or court order | Do not respond informally; take advice (section 5) | Per the order |
| Bug or catalog problem | Fix or remove the entry; note it in the changelog | Reasonable effort |

## 3. Handling a request from the subject of a lookup

1. Acknowledge and ask for what you need to find the data (not more than needed). A name alone usually cannot find anything, because targets are only stored if saved into a case and the audit log holds only keyed hashes. Say so honestly.
2. If the person gives you the target value (for example their email), compute its audit hash and look for matches. The hash is `HMAC-SHA256(APP_SECRET, lowercase(target))`, shortened to 16 hex characters, so you need the same `APP_SECRET` that was in use at the time.
3. Search saved cases for the value and delete matching items if the request is valid.
4. Reply in writing: what you found, what you deleted, what you could not do and why.
5. If misuse is likely, apply section 4.
6. Record the request and what you did (without copying the personal data into the record).

## 4. Handling misuse by a user

1. Preserve the relevant audit-log lines and the saved case (if any) before changing anything.
2. Suspend the user or change the shared password; consider a short note explaining why.
3. Delete saved cases that hold personal data about the affected person.
4. If a crime may have been committed, or someone is in danger, take legal advice and consider contacting the police.
5. Update your rules or settings if the abuse showed a gap. Tell the project via a security report if it was a software gap.

## 5. Legal requests and court orders

- Do not give data out on an informal email or phone call.
- Ask for the request in writing, check the sender and the legal basis, and read exactly what is demanded.
- Take advice before replying.
- Provide only what the lawful request requires and what you actually hold. By design that is little: saved cases (if any), the audit log (types, purposes, keyed hashes) and ordinary server logs.
- Keep a record of the request and your reply.
- Tell the affected user only if the law and the request allow it.

## 6. Records to keep

For each report: date received, who reported, what they said, what you checked, what you did, date closed. Keep the record only as long as needed, and avoid copying personal data into it.

## 7. Transparency

Consider publishing a short yearly note: how many reports you received, how many led to action, how many legal requests you received. It builds trust and shows good faith.
