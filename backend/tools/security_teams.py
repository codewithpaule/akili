"""Red team (offensive recon) and blue team (defensive hardening) assessment layers."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx


RISKY_PORTS = {
    21: "FTP — often cleartext credentials",
    22: "SSH — brute-force surface if exposed",
    23: "Telnet — cleartext remote access",
    25: "SMTP — open relay / spam risk",
    445: "SMB — ransomware lateral movement",
    1433: "MSSQL — database exposure",
    1521: "Oracle DB",
    3306: "MySQL — credential spray target",
    3389: "RDP — common ransomware entry",
    5432: "PostgreSQL",
    5900: "VNC — remote desktop",
    6379: "Redis — often unauthenticated",
    8080: "HTTP alt — admin panels, Jenkins",
    8443: "HTTPS alt — management consoles",
    9200: "Elasticsearch — data exfiltration",
    27017: "MongoDB — NoSQL injection / leak",
}

DEFENSIVE_HEADERS = {
    "strict-transport-security": ("HSTS", "Forces HTTPS — prevents SSL stripping"),
    "content-security-policy": ("CSP", "Mitigates XSS and injection"),
    "x-frame-options": ("Clickjacking", "Prevents iframe embedding attacks"),
    "x-content-type-options": ("MIME sniffing", "Blocks content-type confusion"),
    "referrer-policy": ("Referrer leak", "Limits sensitive URL leakage"),
    "permissions-policy": ("Feature policy", "Restricts browser APIs"),
    "cross-origin-opener-policy": ("COOP", "Isolates browsing context"),
    "cross-origin-resource-policy": ("CORP", "Controls cross-origin reads"),
}


def _host_from_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        return (urlparse(t).hostname or t).lower()
    return t.split("/")[0].split(":")[0].lower()


def run_red_team(target: str, context: dict | None = None) -> dict:
    """Offensive reconnaissance — attack surface mapping without exploitation."""
    context = context or {}
    host = _host_from_target(target)
    findings: list[dict] = []
    raw: dict[str, Any] = {"host": host, "attack_vectors": [], "exposure_score": 0}

    open_ports = context.get("ports") or []
    if not open_ports:
        for tr in context.get("tool_results", []):
            if tr.get("tool") in ("ports", "port_scanner"):
                pr = (tr.get("raw") or {}).get("ports") or []
                open_ports.extend(pr)

    risky_open = []
    for p in open_ports:
        port_num = int(p.get("port", 0) or 0)
        if port_num in RISKY_PORTS and p.get("open"):
            risky_open.append({"port": port_num, "risk": RISKY_PORTS[port_num]})
            findings.append({
                "severity": "HIGH" if port_num in (3389, 445, 6379, 27017, 9200) else "MEDIUM",
                "name": f"Internet-exposed {RISKY_PORTS[port_num].split('—')[0].strip()} (port {port_num})",
                "explanation": RISKY_PORTS[port_num],
                "attack_path": f"Attacker scans port {port_num} → service fingerprint → known exploits or default creds",
            })

    exposed = context.get("exposed_files") or []
    for tr in context.get("tool_results", []):
        if tr.get("tool") == "exposed_files":
            exposed = (tr.get("raw") or {}).get("probes") or exposed

    critical_paths = [p for p in exposed if p.get("accessible") and str(p.get("severity", "")).upper() in ("CRITICAL", "HIGH")]
    for p in critical_paths[:8]:
        findings.append({
            "severity": p.get("severity", "HIGH"),
            "name": f"Sensitive path exposed: {p.get('path', '')}",
            "explanation": "Publicly reachable file or directory that should not be internet-facing",
            "attack_path": "Direct HTTP GET → credential/config leak → lateral movement",
        })
        raw["attack_vectors"].append({"type": "exposed_path", "path": p.get("path")})

    techs = context.get("technologies") or []
    for tr in context.get("tool_results", []):
        if tr.get("tool") in ("tech_fingerprint", "fingerprint"):
            techs = (tr.get("raw") or {}).get("technologies") or techs

    eol_patterns = [
        (r"php/5\.", "PHP 5.x — end-of-life, remote code execution history"),
        (r"php/7\.0|php/7\.1", "PHP 7.0/7.1 — unsupported, patch gap"),
        (r"apache/2\.2", "Apache 2.2 — EOL web server"),
        (r"openssl/1\.0", "OpenSSL 1.0 — Heartbleed-era branch"),
        (r"wordpress.*[34]\.", "WordPress 3.x/4.x — severely outdated"),
    ]
    for tech in techs:
        name = str(tech.get("name") or tech if isinstance(tech, str) else "")
        ver = str(tech.get("version") or "") if isinstance(tech, dict) else ""
        combined = f"{name} {ver}".lower()
        for pat, msg in eol_patterns:
            if re.search(pat, combined, re.I):
                findings.append({
                    "severity": "HIGH",
                    "name": f"End-of-life software: {name} {ver}".strip(),
                    "explanation": msg,
                    "attack_path": "Public CVE databases → exploit module → shell or data access",
                })
                raw["attack_vectors"].append({"type": "eol_software", "tech": name, "version": ver})

    raw["risky_ports"] = risky_open
    raw["exposure_score"] = min(100, len(findings) * 12 + len(risky_open) * 8)

    summary = (
        f"Red team recon on {host or target}: {len(risky_open)} risky ports, "
        f"{len(critical_paths)} critical exposed paths, {len(findings)} attack vectors mapped."
        if findings else f"Red team recon on {host or target}: limited external attack surface detected."
    )

    return {
        "tool": "red_team",
        "severity": "critical" if any(f.get("severity") == "CRITICAL" for f in findings) else "high" if findings else "info",
        "title": "Red team attack surface",
        "summary": summary,
        "findings": findings[:15],
        "raw": raw,
    }


def run_blue_team(target: str, context: dict | None = None) -> dict:
    """Defensive posture review — hardening gaps and monitoring recommendations."""
    context = context or {}
    host = _host_from_target(target)
    url = target if "://" in (target or "") else f"https://{host}"
    findings: list[dict] = []
    raw: dict[str, Any] = {"host": host, "hardening_score": 100, "missing_controls": []}

    headers_map: dict[str, str] = {}
    for tr in context.get("tool_results", []):
        if tr.get("tool") == "headers":
            headers_map = (tr.get("raw") or {}).get("headers") or {}
            break

    if not headers_map:
        try:
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                r = client.get(url, headers={"User-Agent": "AKILI-BlueTeam/1.0"})
                headers_map = {k.lower(): v for k, v in r.headers.items()}
        except Exception:
            pass

    headers_lower = {k.lower(): v for k, v in headers_map.items()}

    for hdr, (label, benefit) in DEFENSIVE_HEADERS.items():
        if hdr not in headers_lower:
            raw["missing_controls"].append(hdr)
            raw["hardening_score"] -= 8
            findings.append({
                "severity": "MEDIUM" if hdr in ("strict-transport-security", "content-security-policy") else "LOW",
                "name": f"Missing {label} header",
                "explanation": benefit,
                "recommendation": f"Add {hdr} response header on all routes",
            })

    if headers_lower.get("server", "").lower() not in ("", "cloudflare", "cloudfront"):
        findings.append({
            "severity": "LOW",
            "name": "Server version disclosure",
            "explanation": f"Server header reveals: {headers_lower.get('server', '')[:80]}",
            "recommendation": "Strip or genericize Server and X-Powered-By headers",
        })
        raw["hardening_score"] -= 5

    if "x-powered-by" in headers_lower:
        findings.append({
            "severity": "LOW",
            "name": "Technology stack disclosure (X-Powered-By)",
            "explanation": headers_lower["x-powered-by"][:120],
            "recommendation": "Remove X-Powered-By in production",
        })
        raw["hardening_score"] -= 5

    raw["hardening_score"] = max(0, min(100, raw["hardening_score"]))

    summary = (
        f"Blue team review: hardening score {raw['hardening_score']}/100 — "
        f"{len(raw['missing_controls'])} security headers missing."
        if raw["missing_controls"]
        else f"Blue team review: hardening score {raw['hardening_score']}/100 — strong baseline."
    )

    return {
        "tool": "blue_team",
        "severity": "medium" if raw["hardening_score"] < 70 else "info",
        "title": "Blue team hardening review",
        "summary": summary,
        "findings": findings[:12],
        "raw": raw,
    }
