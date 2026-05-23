from urllib.parse import urlparse

import dns.resolver
import whois


def _dns_records(hostname: str) -> list[dict]:
    records = []
    record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(hostname, rtype)
            for rdata in answers:
                val = str(rdata)
                if rtype == "MX":
                    val = f"{rdata.preference} {rdata.exchange}"
                records.append({"type": rtype, "value": val[:500]})
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, Exception):
            continue
    return records


def run_dns_only(url: str, context: dict) -> dict:
    hostname = urlparse(url).hostname
    records = _dns_records(hostname)
    context.setdefault("dns_records", records)
    return {
        "tool": "dns",
        "severity": "INFO",
        "title": "DNS records",
        "detail": f"Found {len(records)} DNS records",
        "raw": {"dns": records},
        "findings": [],
    }


def run(url: str, context: dict) -> dict:
    hostname = urlparse(url).hostname
    findings = []
    raw = {"domain": hostname}

    records = _dns_records(hostname)
    raw["dns"] = records
    context["dns_records"] = records

    try:
        w = whois.whois(hostname)
        raw["whois"] = {
            "registrar": str(w.registrar)[:200] if w.registrar else None,
            "creation_date": str(w.creation_date)[:50] if w.creation_date else None,
            "expiration_date": str(w.expiration_date)[:50] if w.expiration_date else None,
            "name_servers": [str(ns)[:100] for ns in (w.name_servers or [])[:5]] if w.name_servers else [],
        }
    except Exception as e:
        raw["whois_error"] = str(e)[:200]
        findings.append({
            "severity": "INFO",
            "name": "WHOIS lookup partial",
            "explanation": "WHOIS data could not be fully retrieved.",
            "recommendation": "Verify domain registration via registrar.",
        })

    if not records:
        findings.append({
            "severity": "MEDIUM",
            "name": "No DNS records found",
            "explanation": "No common DNS records were resolved.",
            "recommendation": "Verify DNS configuration.",
        })

    return {
        "tool": "whois_check",
        "severity": "INFO",
        "title": "WHOIS and DNS",
        "detail": f"{len(records)} DNS records",
        "raw": raw,
        "findings": findings,
    }
