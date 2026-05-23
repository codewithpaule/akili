import httpx

from security import validate_domain, validate_org


def run(target: str, context: dict) -> dict:
    name, domain = target if isinstance(target, tuple) else (target, "")
    if "|" in str(target):
        parts = str(target).split("|", 1)
        name, domain = parts[0].strip(), parts[1].strip()
    name, domain = validate_org(name or domain, domain)

    raw = {"organization": name or domain, "asn": None, "cidr_blocks": [], "hosts": []}

    lookup = domain or name
    if lookup and "." in lookup:
        try:
            r = httpx.get(f"https://api.bgpview.io/asn/0/prefixes/ipv4", timeout=8)
        except Exception:
            pass
        try:
            r = httpx.get(f"https://api.hackertarget.com/aslookup/?q={lookup}", timeout=10)
            if r.status_code == 200 and "No ASN" not in r.text:
                lines = r.text.strip().split("\n")
                raw["asn"] = lines[0][:200] if lines else None
        except Exception:
            pass

    context["org_scan"] = raw
    return {
        "tool": "org_scan",
        "severity": "INFO",
        "title": "Organization scan",
        "detail": raw.get("asn") or "ASN lookup partial",
        "summary": f"Infrastructure footprint analysis for {name or domain}",
        "raw": raw,
        "findings": [],
    }
