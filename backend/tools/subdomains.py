import re
from urllib.parse import urlparse

import httpx
import requests

def run(domain: str, context: dict) -> dict:
    domain = urlparse(domain).hostname if "://" in domain else domain.strip().lower()
    subdomains = []
    hidden_links = []

    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "AKILI/1.0"},
        )
        if r.status_code == 200:
            data = r.json() if r.text.strip().startswith("[") else []
            seen = set()
            for entry in data[:100]:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and sub not in seen:
                        seen.add(sub)
                        subdomains.append({"subdomain": sub, "ip": "", "status": "", "title": ""})
    except Exception:
        pass

    base = f"https://{domain}"
    for path in ("/robots.txt", "/sitemap.xml"):
        try:
            resp = httpx.get(base + path, timeout=8, follow_redirects=True)
            if resp.status_code == 200:
                urls = re.findall(r"https?://[^\s<>\"']+", resp.text)
                hidden_links.extend([{"source": path, "url": u[:300]} for u in urls[:20]])
        except Exception:
            continue

    context["subdomains"] = subdomains
    return {
        "tool": "subdomains",
        "severity": "INFO",
        "title": "Subdomain discovery",
        "detail": f"{len(subdomains)} subdomains",
        "summary": f"Found {len(subdomains)} subdomains via certificate transparency",
        "raw": {"subdomains": subdomains[:50], "hidden_links": hidden_links},
        "findings": [],
    }
