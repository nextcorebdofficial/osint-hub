"""Build github_tools.json: popular open-source OSINT and security projects found through GitHub topics.

Run:  python update_github_tools.py            (uses GITHUB_TOKEN, or `gh auth token`, for a higher rate limit)

Only repositories that have a licence, are not archived or forks and have at least MIN_STARS stars are kept.
Anything that matches the safety filter below is dropped: the hub does not list tools whose main use is to
identify, stalk or harass people, or to attack systems without authorisation (see docs/ETHICS_AND_LEGAL.md).
The catalog entry is a pointer (name, address, the repository's own one-line description); we copy no code.
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx

OUT = Path(__file__).parent / "github_tools.json"
MIN_STARS = 150
PAGES = 2
SCAN_NOTE = " Active scanner: use only on systems you own or are authorised to test."

# Category -> GitHub topics. The first category a repository appears in is the one it keeps.
CATEGORIES = {
    "GitHub: Awesome Lists": ["@awesome osint", "@awesome security", "@awesome hacking", "@awesome threat intelligence",
                              "@awesome forensics", "@awesome pentest", "@awesome incident response",
                              "@awesome malware analysis", "@awesome bug bounty", "@awesome reverse engineering",
                              "@awesome cybersecurity", "@awesome osint tools"],
    "GitHub: OSINT": ["osint", "osint-tool", "osint-framework", "osint-resources", "open-source-intelligence",
                      "osint-tools", "social-media-osint", "email-osint", "domain-osint"],
    "GitHub: Recon & Subdomains": ["reconnaissance", "recon", "subdomain-enumeration", "information-gathering",
                                   "asset-discovery", "attack-surface-management", "subdomain-scanner",
                                   "recon-framework"],
    "GitHub: Threat Intelligence": ["threat-intelligence", "cti", "threat-hunting", "threat-detection", "ioc", "misp",
                                    "indicators-of-compromise", "threat-feed"],
    "GitHub: Digital Forensics & DFIR": ["dfir", "digital-forensics", "forensics", "incident-response",
                                         "memory-forensics", "forensic-analysis", "disk-forensics"],
    "GitHub: Malware Analysis": ["malware-analysis", "yara", "reverse-engineering", "binary-analysis",
                                 "malware-research", "disassembler", "decompiler"],
    "GitHub: Network Security & Monitoring": ["intrusion-detection", "ids", "siem", "network-security",
                                              "network-monitoring", "zeek", "suricata", "packet-analysis",
                                              "wireshark", "network-forensics", "xdr", "edr"],
    "GitHub: Blue Team & Detection": ["blue-team", "security-hardening", "soc", "detection-engineering", "sigma",
                                      "threat-modeling", "security-monitoring", "honeypot"],
    "GitHub: Web & App Security": ["web-security", "owasp", "appsec", "devsecops", "security-audit", "waf",
                                   "web-application-security", "security-headers"],
    "GitHub: Cloud & Container Security": ["cloud-security", "kubernetes-security", "container-security",
                                           "aws-security", "iac-security", "cspm", "docker-security"],
    "GitHub: Secrets & Leak Prevention": ["secret-scanning", "secrets-detection", "secrets-management",
                                          "git-secrets", "credential-scanning"],
    "GitHub: DNS, Certificates & TLS": ["dns-enumeration", "certificate-transparency", "ssl-scanner", "tls-scanner",
                                        "dns-tools", "whois", "bgp"],
    "GitHub: Geospatial & Image OSINT": ["geoint", "geolocation", "satellite-imagery", "image-forensics", "exif",
                                         "metadata", "reverse-image-search", "photo-geolocation"],
    "GitHub: Web Archiving & Collection": ["web-archiving", "wayback-machine", "internet-archive", "web-archive",
                                           "archivebox"],
    "GitHub: Link Analysis & Graphs": ["link-analysis", "knowledge-graph", "graph-visualization", "entity-resolution",
                                       "network-analysis", "investigation", "case-management"],
    "GitHub: Fact-checking & Verification": ["fact-checking", "disinformation", "misinformation",
                                             "media-verification", "deepfake-detection", "propaganda-detection"],
    "GitHub: Privacy & Anonymity": ["privacy-tools", "anonymity", "tor", "opsec", "privacy-protection", "anti-tracking",
                                    "metadata-removal"],
    "GitHub: Security Learning & CTF": ["ctf", "ctf-tools", "security-training", "cybersecurity-education",
                                        "capture-the-flag", "hacking-lab"],
}
SCANNER_CATEGORIES: set[str] = set()  # offensive and scanner categories are not imported (see docs/SAFE_LAUNCH.md)

# Dropped when found in the name, description or topics.
DENY = re.compile(
    r"\b(dox+(ing)?|stalk\w*|face[- ]?(recogni\w*|search|match\w*|swap)|facial|deepface|insightface|face_recognition|"
    r"phone[- ]?numbers?|caller[- ]?id|truecaller|leak(ed)?[- ]?(db|database|data|passwords?|credentials?)|"
    r"combo[- ]?lists?|credential[- ]?stuff\w*|ddos|booter|stresser|ransomware|keylogg\w*|stealer|infostealer|"
    r"rat|botnet|spyware|stalkerware|sms[- ]?bomb\w*|call[- ]?bomb\w*|carding|crack(er|ing)?|brute[- ]?forc\w*|"
    r"exploit\w*|0-?day|weaponi[sz]\w*|payload[- ]?generator|c2|command[- ]and[- ]control|av[- ]?evasion|"
    r"undetectable|fud|phishing[- ]?(kit|framework|page)|credential[- ]?harvest\w*|webcam[- ]?hack\w*|"
    r"track(ing)?[- ]?(a[- ])?(person|people|someone|girlfriend|boyfriend|wife|husband)|ip[- ]?grabber|"
    r"social[- ]?engineer\w*[- ]?toolkit|keystroke|backdoor|rootkit|trojan|cheat|hack(ing)?[- ]?(facebook|instagram|"
    r"whatsapp|gmail|account)s?|nsfw|porn\w*|onlyfans|deanonymi[sz]\w*)\b", re.I)


def token() -> str:
    t = os.environ.get("GITHUB_TOKEN", "").strip()
    if t:
        return t
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        return ""


def search(client: httpx.Client, q: str, page: int) -> list[dict]:
    for attempt in range(4):
        r = client.get("https://api.github.com/search/repositories",
                       params={"q": q, "sort": "stars", "order": "desc", "per_page": 100, "page": page})
        if r.status_code == 200:
            return r.json().get("items", [])
        if r.status_code in (403, 429):
            wait = int(r.headers.get("retry-after", "0") or 0) or 30 * (attempt + 1)
            print(f"  rate limited, waiting {wait}s", flush=True)
            time.sleep(wait)
            continue
        print(f"  skipped ({r.status_code}): {q}", flush=True)
        return []
    return []


def human(n: int) -> str:
    return f"{n / 1000:.1f}k".replace(".0k", "k") if n >= 1000 else str(n)


def keep(repo: dict) -> bool:
    if repo.get("archived") or repo.get("fork") or repo.get("private"):
        return False
    if not repo.get("license") or repo.get("stargazers_count", 0) < MIN_STARS:
        return False
    text = " ".join([repo.get("full_name", ""), repo.get("description") or "", " ".join(repo.get("topics", []))])
    return not DENY.search(text)


def main() -> int:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "OSINT-Hub-catalog-updater"}
    tok = token()
    if tok:
        headers["Authorization"] = "Bearer " + tok
    delay = 2.2 if tok else 7.0  # search API: 30 requests a minute with a token, 10 without
    seen: set[str] = set()
    out: list[dict] = []
    with httpx.Client(headers=headers, timeout=30) as client:
        for cat, topics in CATEGORIES.items():
            before = len(out)
            for topic in topics:
                q = (f"{topic[1:]} in:name,description" if topic.startswith("@") else f"topic:{topic}")
                q += f" stars:>={MIN_STARS} archived:false"
                for page in range(1, PAGES + 1):
                    items = search(client, q, page)
                    time.sleep(delay)
                    for repo in items:
                        url = repo["html_url"].lower()
                        if url in seen or not keep(repo):
                            continue
                        if topic.startswith("@") and "awesome" not in repo["name"].lower():
                            continue
                        seen.add(url)
                        desc = " ".join((repo.get("description") or "").split())[:200]
                        meta = f"★{human(repo['stargazers_count'])}" + (f", {repo['language']}" if repo.get("language") else "")
                        out.append({
                            "name": repo["full_name"], "url": repo["html_url"], "category": cat,
                            "description": (desc + " " if desc else "") + f"({meta})"
                                           + (SCAN_NOTE if cat in SCANNER_CATEGORIES else ""),
                            "pricing": "free", "local": True, "stars": repo["stargazers_count"]})
                    if len(items) < 100:
                        break
            print(f"{cat}: +{len(out) - before}", flush=True)
    out.sort(key=lambda e: (list(CATEGORIES).index(e["category"]), -e["stars"]))
    for e in out:
        del e["stars"]
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(out)} entries to {OUT.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
