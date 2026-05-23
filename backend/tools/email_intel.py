import dns.resolver
import httpx

from tools.fallbacks import check_email_breach


def run(email: str, context: dict) -> dict:
    findings = []
    domain = email.split("@")[-1]
    raw = {"email": email, "mx_valid": False, "disposable": False, "breaches": [], "gravatar": False}

    disposable_domains = {"mailinator.com", "guerrillamail.com", "tempmail.com", "10minutemail.com"}
    if domain.lower() in disposable_domains:
        raw["disposable"] = True
        findings.append({
            "severity": "MEDIUM",
            "name": "Disposable email domain",
            "explanation": f"Domain {domain} is a known disposable provider.",
            "recommendation": "Use a corporate email for trust signals.",
        })

    try:
        dns.resolver.resolve(domain, "MX")
        raw["mx_valid"] = True
    except Exception:
        findings.append({
            "severity": "HIGH",
            "name": "No MX records",
            "explanation": "Domain has no mail exchange records.",
            "recommendation": "Verify domain is configured for email.",
        })

    try:
        h = httpx.head(f"https://www.gravatar.com/avatar/{email.strip().lower()}", timeout=5)
        raw["gravatar"] = h.status_code == 200
    except Exception:
        pass

    breach_result = check_email_breach(email)
    raw["breach_check"] = breach_result
    raw["pwned"] = breach_result.get("pwned") or bool(breach_result.get("breaches"))
    if breach_result.get("breaches"):
        raw["breaches"] = breach_result["breaches"]
        src = breach_result.get("source", "breach database")
        findings.append({
            "severity": "HIGH",
            "name": "Email found in breach database",
            "explanation": f"{breach_result.get('breach_count', 0)} breach(es) via {src}.",
            "recommendation": "Rotate passwords for affected sites and enable MFA.",
        })
    elif not raw["breaches"] and "xposedornot" in (breach_result.get("source") or "").lower():
        findings.append({
            "severity": "INFO",
            "name": "No breaches in free databases",
            "explanation": "Email not found in XposedOrNot's breach index (free, no API key).",
            "recommendation": "Keep using unique passwords and MFA.",
        })

    context["email_intel"] = raw
    return {
        "tool": "email_intel",
        "severity": "HIGH" if raw["breaches"] else "INFO",
        "title": "Email investigation",
        "detail": f"{len(raw['breaches'])} breach(es) — {breach_result.get('source', 'checked')}" if raw["breaches"] else f"MX checked — {breach_result.get('source', 'no breaches')}",
        "summary": (
            f"Pwned in {len(raw['breaches'])} breach(es) ({breach_result.get('source', '')})"
            if raw["breaches"]
            else f"No breaches found ({breach_result.get('source', 'checked')})"
        ),
        "raw": raw,
        "findings": findings,
    }
