"""Lookups behind the investigation endpoints. API keys are read from the environment."""
import asyncio
import hashlib
import ipaddress
import os
import re
import socket
from urllib.parse import quote, urljoin, urlparse

import httpx
import phonenumbers
from phonenumbers import carrier, geocoder, timezone

KEY_NAMES = ["HIBP_API_KEY", "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY",
             "SECURITYTRAILS_API_KEY"]


def env(name: str) -> str:
    return os.environ.get(name, "").strip()


def configured_keys() -> dict:
    return {k: bool(env(k)) for k in KEY_NAMES}


async def _get_json(client: httpx.AsyncClient, url: str, **kw):
    try:
        r = await client.get(url, **kw)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None


# ------------------------------------------------------------------ DNS / domain

async def dns_records(client, name: str) -> dict:
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results = await asyncio.gather(*[
        _get_json(client, "https://dns.google/resolve", params={"name": name, "type": t})
        for t in types
    ])
    out = {}
    for t, data in zip(types, results):
        answers = [a["data"] for a in (data or {}).get("Answer", []) if a.get("type") is not None]
        if answers:
            out[t] = answers
    return out


async def wayback(client, target: str) -> dict:
    first, last, avail = await asyncio.gather(
        _get_json(client, "https://web.archive.org/cdx/search/cdx",
                  params={"url": target, "output": "json", "fl": "timestamp", "limit": 1}),
        _get_json(client, "https://web.archive.org/cdx/search/cdx",
                  params={"url": target, "output": "json", "fl": "timestamp", "limit": -1}),
        _get_json(client, "https://archive.org/wayback/available", params={"url": target}),
    )
    out = {"browse": f"https://web.archive.org/web/*/{target}"}
    if first and len(first) > 1:
        out["first_snapshot"] = first[1][0]
    if last and len(last) > 1:
        out["last_snapshot"] = last[1][0]
    snap = ((avail or {}).get("archived_snapshots") or {}).get("closest")
    if snap:
        out["closest_snapshot_url"] = snap.get("url")
    return out


async def vt_lookup(client, kind: str, value: str) -> dict:
    if not env("VIRUSTOTAL_API_KEY"):
        return {"info": "set VIRUSTOTAL_API_KEY to enable"}
    path = "domains" if kind == "domain" else "ip_addresses"
    data = await _get_json(client, f"https://www.virustotal.com/api/v3/{path}/{value}",
                           headers={"x-apikey": env("VIRUSTOTAL_API_KEY")})
    if not data:
        return {"error": "no data or request failed"}
    a = data["data"]["attributes"]
    return {"reputation": a.get("reputation"), "last_analysis_stats": a.get("last_analysis_stats"),
            "link": f"https://www.virustotal.com/gui/{kind}/{value}"}


async def securitytrails(client, domain: str) -> dict:
    key = env("SECURITYTRAILS_API_KEY")
    if not key:
        return {"info": "set SECURITYTRAILS_API_KEY to enable"}
    h = {"APIKEY": key, "Accept": "application/json"}
    base = "https://api.securitytrails.com/v1"
    subs, hist = await asyncio.gather(
        _get_json(client, f"{base}/domain/{domain}/subdomains",
                  params={"children_only": "false", "include_inactive": "true"}, headers=h),
        _get_json(client, f"{base}/history/{domain}/dns/a", headers=h))
    if subs is None and hist is None:
        return {"error": "request failed (check the key and your plan's limits)"}
    out = {}
    if subs:
        names = sorted(f"{s}.{domain}" for s in subs.get("subdomains", []))
        out["subdomains"] = names[:500]
        out["subdomain_count"] = len(names)
    if hist:
        out["a_record_history"] = [
            {"ips": [v.get("ip") for v in r.get("values", [])], "first_seen": r.get("first_seen"),
             "last_seen": r.get("last_seen"), "organizations": r.get("organizations")}
            for r in hist.get("records", [])[:20]]
    return out


async def lookup_domain(client, domain: str) -> dict:
    dns, rdap, crt, wb, vt, st = await asyncio.gather(
        dns_records(client, domain),
        _get_json(client, f"https://rdap.org/domain/{domain}", follow_redirects=True),
        _get_json(client, "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=25),
        wayback(client, domain),
        vt_lookup(client, "domain", domain),
        securitytrails(client, domain),
    )
    out = {"dns": dns}
    if rdap:
        events = {e.get("eventAction"): e.get("eventDate") for e in rdap.get("events", [])}
        out["rdap"] = {
            "status": rdap.get("status"),
            "events": events,
            "nameservers": [n.get("ldhName") for n in rdap.get("nameservers", [])],
            "registrar": next((
                v[3] for e in rdap.get("entities", []) if "registrar" in e.get("roles", [])
                for v in [x for x in e.get("vcardArray", [None, []])[1] if x[0] == "fn"]
            ), None),
        }
    if crt:
        subs = set()
        for row in crt:
            for n in str(row.get("name_value", "")).split("\n"):
                subs.add(n.strip().lower().lstrip("*."))
        out["subdomains_crtsh"] = sorted(subs)
    out["wayback"] = wb
    out["virustotal"] = vt
    out["securitytrails"] = st
    return out


# ------------------------------------------------------------------ IP

async def ip_enrichment(client, ip: str) -> dict:
    out = {}
    if env("SHODAN_API_KEY"):
        d = await _get_json(client, f"https://api.shodan.io/shodan/host/{ip}", params={"key": env("SHODAN_API_KEY")})
        out["shodan"] = {k: d.get(k) for k in ("ports", "hostnames", "org", "os", "vulns")} if d else {
            "info": "no Shodan data for this IP"}
    else:
        out["shodan"] = {"info": "set SHODAN_API_KEY to enable"}
    if env("ABUSEIPDB_API_KEY"):
        d = await _get_json(client, "https://api.abuseipdb.com/api/v2/check",
                            params={"ipAddress": ip, "maxAgeInDays": 90},
                            headers={"Key": env("ABUSEIPDB_API_KEY"), "Accept": "application/json"})
        out["abuseipdb"] = {k: d["data"].get(k) for k in (
            "abuseConfidenceScore", "totalReports", "usageType", "isp", "domain")} if d else {
            "error": "request failed"}
    else:
        out["abuseipdb"] = {"info": "set ABUSEIPDB_API_KEY to enable"}
    out["virustotal"] = await vt_lookup(client, "ip", ip)
    return out


async def lookup_ip(client, ip: str) -> dict:
    geo, rdap, ptr, enrich = await asyncio.gather(
        _get_json(client, f"https://ipwho.is/{ip}"),
        _get_json(client, f"https://rdap.org/ip/{ip}", follow_redirects=True),
        _get_json(client, "https://dns.google/resolve", params={
            "name": ipaddress.ip_address(ip).reverse_pointer, "type": "PTR"}),
        ip_enrichment(client, ip),
    )
    out = {}
    if geo:
        out["geo"] = {k: geo.get(k) for k in ("country", "region", "city", "latitude", "longitude", "type")}
        out["network"] = geo.get("connection")
    if rdap:
        out["rdap"] = {k: rdap.get(k) for k in ("name", "handle", "startAddress", "endAddress", "country", "type")}
    out["reverse_dns"] = [a["data"] for a in (ptr or {}).get("Answer", [])]
    out.update(enrich)
    return out


# ------------------------------------------------------------------ email

async def hibp(client, email: str) -> dict:
    if not env("HIBP_API_KEY"):
        return {"info": "set HIBP_API_KEY to enable the breach check"}
    try:
        r = await client.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                             params={"truncateResponse": "true"}, headers={"hibp-api-key": env("HIBP_API_KEY")})
    except Exception as e:
        return {"error": str(e)}
    if r.status_code == 404:
        return {"breaches": []}
    if r.status_code == 200:
        return {"breaches": [b["Name"] for b in r.json()]}
    return {"error": f"HTTP {r.status_code}"}


async def lookup_email(client, email: str) -> dict:
    domain = email.split("@", 1)[1].lower()
    digest = hashlib.md5(email.strip().lower().encode()).hexdigest()
    dns, grav, breaches = await asyncio.gather(
        dns_records(client, domain),
        client.get(f"https://www.gravatar.com/avatar/{digest}", params={"d": "404"}),
        hibp(client, email),
    )
    return {
        "domain": domain,
        "mx": dns.get("MX", []),
        "has_mx": bool(dns.get("MX")),
        "spf": [t for t in dns.get("TXT", []) if "v=spf1" in t],
        "gravatar_profile_exists": grav.status_code == 200,
        "breaches": breaches,
    }


# ------------------------------------------------------------------ username

_wmn_cache: list | None = None


async def _wmn_sites(client) -> list:
    global _wmn_cache
    if _wmn_cache is None:
        data = await _get_json(
            client, "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json", timeout=30)
        _wmn_cache = (data or {}).get("sites", [])
    return _wmn_cache


async def lookup_username(client, username: str, limit: int, progress: dict | None = None) -> dict:
    sites = (await _wmn_sites(client))[:limit]
    progress = progress if progress is not None else {}
    progress.update(checked=0, total=len(sites))
    sem = asyncio.Semaphore(40)
    found = []
    safe = quote(username, safe="")

    async def check(site):
        url = site["uri_check"].replace("{account}", safe)
        async with sem:
            try:
                r = await client.get(url, timeout=8, follow_redirects=True)
            except Exception:
                progress["checked"] += 1
                return
        progress["checked"] += 1
        if r.status_code == site.get("e_code") and site.get("e_string", "") in r.text \
                and (not site.get("m_string") or site["m_string"] not in r.text):
            found.append({"site": site["name"], "category": site.get("cat"),
                          "url": site.get("uri_pretty", url).replace("{account}", safe)})

    await asyncio.gather(*[check(s) for s in sites])
    return {"sites_checked": progress["checked"], "sites_total": len(await _wmn_sites(client)),
            "found": sorted(found, key=lambda x: x["site"].lower())}


# ------------------------------------------------------------------ phone

PHONE_TYPES = {v: k for k, v in vars(phonenumbers.PhoneNumberType).items() if k.isupper()}


def lookup_phone(raw: str, region: str | None) -> dict:
    """Offline parsing of the number itself: validity, country, line type, carrier, time zones."""
    try:
        num = phonenumbers.parse(raw, region)
    except phonenumbers.NumberParseException as e:
        return {"error": f"{e}. Include the country code (+880...) or pass a region like BD."}
    fmt = phonenumbers.PhoneNumberFormat
    return {
        "valid": phonenumbers.is_valid_number(num),
        "possible": phonenumbers.is_possible_number(num),
        "e164": phonenumbers.format_number(num, fmt.E164),
        "international": phonenumbers.format_number(num, fmt.INTERNATIONAL),
        "country_code": num.country_code,
        "region": phonenumbers.region_code_for_number(num),
        "location": geocoder.description_for_number(num, "en"),
        "line_type": PHONE_TYPES.get(phonenumbers.number_type(num), "UNKNOWN"),
        "original_carrier": carrier.name_for_number(num, "en") or None,
        "timezones": list(timezone.time_zones_for_number(num)),
        "note": "Carrier is the original allocation; ported numbers may differ.",
    }


# ------------------------------------------------------------------ crypto

async def lookup_crypto(client, addr: str) -> dict:
    """Public on-chain data for a Bitcoin or Ethereum address."""
    if addr.startswith("0x"):
        info, counters = await asyncio.gather(
            _get_json(client, f"https://eth.blockscout.com/api/v2/addresses/{addr}"),
            _get_json(client, f"https://eth.blockscout.com/api/v2/addresses/{addr}/counters"),
        )
        if not info:
            return {"chain": "ethereum", "error": "address not found or explorer unavailable"}
        wei = int(info.get("coin_balance") or 0)
        return {
            "chain": "ethereum",
            "balance_eth": wei / 1e18,
            "is_contract": info.get("is_contract"),
            "public_name": info.get("name"),
            "ens": info.get("ens_domain_name"),
            "transactions": (counters or {}).get("transactions_count"),
            "token_transfers": (counters or {}).get("token_transfers_count"),
            "explorer": f"https://eth.blockscout.com/address/{addr}",
        }
    data = await _get_json(client, f"https://blockstream.info/api/address/{addr}")
    if not data:
        return {"chain": "bitcoin", "error": "address not found or explorer unavailable"}
    chain, mem = data["chain_stats"], data["mempool_stats"]
    return {
        "chain": "bitcoin",
        "balance_btc": (chain["funded_txo_sum"] - chain["spent_txo_sum"]) / 1e8,
        "total_received_btc": chain["funded_txo_sum"] / 1e8,
        "total_sent_btc": chain["spent_txo_sum"] / 1e8,
        "transactions": chain["tx_count"],
        "unconfirmed_transactions": mem["tx_count"],
        "explorer": f"https://blockstream.info/address/{addr}",
    }


# ------------------------------------------------------------------ URL

async def resolve_public(host: str) -> bool:
    """True only if every address the host resolves to is a public one (SSRF guard)."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except socket.gaierror:
        return False
    try:
        return bool(infos) and all(ipaddress.ip_address(i[4][0].split("%")[0]).is_global for i in infos)
    except ValueError:
        return False


async def lookup_url(client, url: str) -> dict:
    hops, cur = [], url
    body = b""
    headers = {}
    for _ in range(8):
        p = urlparse(cur)
        if p.scheme not in ("http", "https") or not p.hostname or not await resolve_public(p.hostname):
            return {"error": "blocked or invalid URL (only public http/https hosts are fetched)", "hops": hops}
        try:
            async with client.stream("GET", cur, follow_redirects=False, timeout=15) as r:
                body = b""
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) > 200_000:
                        break
                hops.append({"url": cur, "status": r.status_code})
                headers = dict(r.headers)
                loc = r.headers.get("location")
        except Exception as e:
            return {"error": str(e), "hops": hops}
        if hops[-1]["status"] in (301, 302, 303, 307, 308) and loc:
            cur = urljoin(cur, loc)
            continue
        break
    else:
        return {"error": "too many redirects", "hops": hops}
    title = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    host = urlparse(cur).hostname
    return {
        "final_url": cur,
        "status": hops[-1]["status"],
        "redirect_chain": hops,
        "title": title.group(1).decode("utf-8", "replace").strip()[:200] if title else None,
        "headers": {k: headers[k] for k in (
            "server", "content-type", "x-powered-by", "x-frame-options", "strict-transport-security",
            "content-security-policy", "last-modified", "via") if k in headers},
        "host": host,
        "wayback": await wayback(client, url),
    }


# ------------------------------------------------------------------ company

_sec_cache: list | None = None


async def _sec_tickers(client) -> list:
    global _sec_cache
    if _sec_cache is None:
        data = await _get_json(client, "https://www.sec.gov/files/company_tickers.json",
                               headers={"User-Agent": env("SEC_USER_AGENT") or "OSINT-Hub/1.0 admin@localhost"})
        _sec_cache = list((data or {}).values())
    return _sec_cache


async def lookup_company(client, name: str) -> dict:
    gleif, sec = await asyncio.gather(
        _get_json(client, "https://api.gleif.org/api/v1/lei-records",
                  params={"filter[fulltext]": name, "page[size]": 5}),
        _sec_tickers(client),
    )
    ql = name.lower()
    matches = [c for c in sec if ql in c["title"].lower() or c["ticker"].lower() == ql][:10]
    entities = []
    for rec in (gleif or {}).get("data", []):
        ent = rec.get("attributes", {}).get("entity", {})
        addr = ent.get("legalAddress", {})
        entities.append({
            "lei": rec.get("id"),
            "legal_name": (ent.get("legalName") or {}).get("name"),
            "jurisdiction": ent.get("jurisdiction"),
            "status": ent.get("status"),
            "city": addr.get("city"),
            "country": addr.get("country"),
            "record": f"https://search.gleif.org/#/record/{rec.get('id')}",
        })
    return {
        "gleif_legal_entities": entities,
        "sec_edgar_matches": [{
            "name": c["title"], "ticker": c["ticker"], "cik": c["cik_str"],
            "filings": f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={c['cik_str']}",
        } for c in matches],
        "search_links": {
            "opencorporates": f"https://opencorporates.com/companies?q={quote(name)}",
            "sec_fulltext": f"https://efts.sec.gov/LATEST/search-index?q={quote(name)}",
        },
    }
