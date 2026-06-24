import os
import re
import socket

import httpx
import requests
from dotenv import load_dotenv

load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")


def _probe_site_title(hostname: str) -> dict:
    """Fetch page title for a hostname linked to this IP."""
    if not hostname or re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
        return {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            from http_client import get_sync_client
            client = get_sync_client()
            r = client.get(url, headers={"User-Agent": "AKILI-Platform/2.0"})
            html = (r.text or "")[:80000]
            tm = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
            title = re.sub(r"\s+", " ", tm.group(1)).strip()[:200] if tm else ""
            return {"url": str(r.url), "title": title, "status_code": r.status_code}
        except Exception:
            continue
    return {"url": f"https://{hostname}", "title": "", "status_code": None}


def _collect_hostnames(ip: str, reverse_dns: str | None, shodan_data: dict | None) -> list[str]:
    names: list[str] = []
    if reverse_dns:
        names.append(reverse_dns.rstrip(".").lower())
    if shodan_data:
        for h in shodan_data.get("hostnames") or []:
            if h:
                names.append(str(h).rstrip(".").lower())
        domains_field = shodan_data.get("domains")
        if isinstance(domains_field, str):
            for d in domains_field.split(";"):
                d = d.strip().lower()
                if d and d not in names:
                    names.append(d)
        elif isinstance(domains_field, list):
            for d in domains_field:
                if d:
                    names.append(str(d).rstrip(".").lower())
    seen: set[str] = set()
    out = []
    for n in names:
        if n and n not in seen and not re.match(r"^\d+\.\d+\.\d+\.\d+$", n):
            seen.add(n)
            out.append(n)
    return out[:15]


def run(ip: str, context: dict) -> dict:
    findings = []
    raw = {
        "ip": ip,
        "geolocation": {},
        "ports": [],
        "blacklisted": False,
        "reverse_dns": None,
        "hosted_domains": [],
        "hosted_websites": [],
        "primary_website": None,
    }

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query,reverse",
            timeout=8,
        )
        if resp.status_code == 200:
            geo = resp.json()
            if geo.get("status") == "success":
                raw["geolocation"] = {
                    "country": geo.get("country"),
                    "city": geo.get("city"),
                    "isp": geo.get("isp"),
                    "org": geo.get("org"),
                    "asn": geo.get("as"),
                }
                if geo.get("reverse"):
                    raw["reverse_dns"] = geo["reverse"]
    except Exception:
        pass

    if not raw["reverse_dns"]:
        try:
            raw["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            raw["reverse_dns"] = None

    shodan_data = None
    if SHODAN_API_KEY:
        try:
            s = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=12)
            if s.status_code == 200:
                shodan_data = s.json()
                raw["ports"] = [
                    {"port": p, "service": "open", "status": "open", "risk": "review"}
                    for p in (shodan_data.get("ports") or [])[:25]
                ]
                raw["shodan_org"] = shodan_data.get("org")
                raw["shodan_os"] = shodan_data.get("os")
        except Exception:
            pass

    hostnames = _collect_hostnames(ip, raw.get("reverse_dns"), shodan_data)
    raw["hosted_domains"] = hostnames
    websites = []
    for host in hostnames[:8]:
        probe = _probe_site_title(host)
        entry = {
            "hostname": host,
            "url": probe.get("url") or f"https://{host}",
            "title": probe.get("title") or "",
            "status_code": probe.get("status_code"),
        }
        websites.append(entry)
    raw["hosted_websites"] = websites
    if websites:
        raw["primary_website"] = websites[0]
        findings.append({
            "severity": "INFO",
            "name": "Website(s) on this IP",
            "explanation": f"Primary host: {websites[0]['hostname']}"
            + (f" — “{websites[0]['title']}”" if websites[0].get("title") else ""),
            "recommendation": "Open the linked site to confirm it matches expectations.",
        })

    context["ip_intel"] = raw
    loc = raw["geolocation"].get("country", "Unknown")
    summary = f"IP in {loc}"
    if raw.get("primary_website"):
        summary += f" — serves {raw['primary_website']['hostname']}"
    return {
        "tool": "ip_intel",
        "severity": "INFO",
        "title": "IP intelligence",
        "detail": loc,
        "summary": summary,
        "raw": raw,
        "findings": findings,
    }
