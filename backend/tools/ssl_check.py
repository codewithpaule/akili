import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def run(url: str, context: dict) -> dict:
    hostname = urlparse(url).hostname
    port = urlparse(url).port or (443 if urlparse(url).scheme == "https" else 443)
    findings = []
    raw = {}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

        raw["protocol"] = protocol
        raw["cipher"] = cipher[0] if cipher else None
        not_after = cert.get("notAfter")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            raw["days_remaining"] = days_left
            raw["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            raw["subject"] = dict(x[0] for x in cert.get("subject", []))

            if days_left < 0:
                findings.append({
                    "severity": "CRITICAL",
                    "name": "SSL certificate expired",
                    "explanation": f"Certificate expired {abs(days_left)} days ago.",
                    "recommendation": "Renew the SSL certificate immediately.",
                })
            elif days_left < 30:
                findings.append({
                    "severity": "HIGH",
                    "name": "SSL certificate expiring soon",
                    "explanation": f"Certificate expires in {days_left} days.",
                    "recommendation": "Renew the certificate before expiry.",
                })
            else:
                findings.append({
                    "severity": "INFO",
                    "name": "SSL certificate valid",
                    "explanation": f"Certificate valid, {days_left} days remaining.",
                    "recommendation": "Monitor renewal dates.",
                })

        if protocol and "TLSv1.0" in protocol or (protocol and "TLSv1.1" in protocol):
            findings.append({
                "severity": "HIGH",
                "name": "Outdated TLS protocol",
                "explanation": f"Server uses {protocol}.",
                "recommendation": "Disable TLS 1.0/1.1; use TLS 1.2+ only.",
            })

    except ssl.SSLError as e:
        findings.append({
            "severity": "CRITICAL",
            "name": "SSL/TLS error",
            "explanation": str(e)[:200],
            "recommendation": "Fix SSL configuration on the server.",
        })
        raw["error"] = str(e)
    except Exception as e:
        findings.append({
            "severity": "MEDIUM",
            "name": "SSL check failed",
            "explanation": str(e)[:200],
            "recommendation": "Verify HTTPS is enabled and port 443 is open.",
        })
        raw["error"] = str(e)

    severity = "INFO"
    if any(f["severity"] == "CRITICAL" for f in findings):
        severity = "CRITICAL"
    elif any(f["severity"] == "HIGH" for f in findings):
        severity = "HIGH"

    return {
        "tool": "ssl",
        "severity": severity,
        "title": "SSL/TLS analysis",
        "detail": raw.get("days_remaining", "N/A"),
        "raw": raw,
        "findings": findings,
    }
