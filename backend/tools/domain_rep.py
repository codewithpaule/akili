import os
from datetime import datetime

import httpx
import requests
import whois
from dotenv import load_dotenv

from security import validate_domain

load_dotenv()
VT_KEY = os.getenv("VIRUSTOTAL_KEY", "")


def run(domain: str, context: dict) -> dict:
    domain = validate_domain(domain)
    raw = {
        "domain": domain,
        "safe_browsing": "unknown",
        "blacklisted": False,
        "virustotal": {},
        "age_years": None,
        "typosquats": [],
    }
    findings = []

    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age = (datetime.now() - created).days / 365
            raw["age_years"] = round(age, 1)
            if age < 0.5:
                findings.append({
                    "severity": "MEDIUM",
                    "name": "Recently registered domain",
                    "explanation": f"Domain age ~{raw['age_years']} years.",
                    "recommendation": "Verify domain ownership for new registrations.",
                })
    except Exception:
        pass

    if VT_KEY:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VT_KEY},
                timeout=12,
            )
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                raw["virustotal"] = stats
                if stats.get("malicious", 0) > 0:
                    findings.append({
                        "severity": "CRITICAL",
                        "name": "VirusTotal detections",
                        "explanation": f"{stats.get('malicious')} vendors flagged domain.",
                        "recommendation": "Avoid interaction until cleared.",
                    })
        except Exception:
            pass

    for typo in [domain.replace("o", "0"), domain.replace("i", "1")]:
        if typo != domain:
            raw["typosquats"].append(typo)

    context["domain_rep"] = raw
    return {
        "tool": "domain_rep",
        "severity": "CRITICAL" if findings else "INFO",
        "title": "Domain reputation",
        "detail": f"Age: {raw.get('age_years', '?')}y",
        "summary": "Domain reputation analysis complete",
        "raw": raw,
        "findings": findings,
    }
