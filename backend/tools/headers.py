import re
from urllib.parse import urlparse

import httpx

INSTITUTIONAL_TLD = re.compile(
    r"\.(edu|edu\.ng|edu\.[a-z]{2}|ac\.uk|gov|gov\.ng|mil)(?:$|:)",
    re.I,
)


def _is_institutional(hostname: str | None) -> bool:
    if not hostname:
        return False
    h = hostname.lower()
    return bool(INSTITUTIONAL_TLD.search(h)) or "university" in h or "college" in h or "school" in h


SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "HIGH"),
    "content-security-policy": ("CSP", "HIGH"),
    "x-frame-options": ("X-Frame-Options", "MEDIUM"),
    "x-content-type-options": ("X-Content-Type-Options", "MEDIUM"),
    "referrer-policy": ("Referrer-Policy", "LOW"),
    "permissions-policy": ("Permissions-Policy", "LOW"),
    "x-xss-protection": ("X-XSS-Protection", "INFO"),
}


def run(url: str, context: dict) -> dict:
    hostname = urlparse(url).hostname
    findings = []
    raw_headers = {}

    resp = None
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True, max_redirects=3) as client:
            resp = client.get(url, headers={"User-Agent": "AKILI-Security-Audit/1.0"})
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as e:
        return {
            "tool": "headers",
            "severity": "MEDIUM",
            "title": "Could not fetch headers",
            "detail": str(e)[:200],
            "raw": {"error": str(e)},
            "findings": [{
                "severity": "MEDIUM",
                "name": "HTTP request failed",
                "explanation": str(e)[:200],
                "recommendation": "Ensure the URL is reachable over HTTPS.",
            }],
        }

    institutional = _is_institutional(hostname)
    for header_key, (name, default_sev) in SECURITY_HEADERS.items():
        if header_key not in raw_headers:
            sev = "INFO" if institutional and default_sev in ("HIGH", "MEDIUM") else default_sev
            findings.append({
                "severity": sev,
                "name": f"Missing {name} header",
                "explanation": (
                    f"The {name} security header was not present."
                    + (" Common on university/government sites; still worth adding." if institutional else "")
                ),
                "recommendation": f"Configure your web server to send a proper {name} header.",
            })

    server = raw_headers.get("server", "")
    powered = raw_headers.get("x-powered-by", "")
    page_title = ""
    page_description = ""
    if resp is not None:
        html = (resp.text or "")[:120000]
        tm = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
        if tm:
            page_title = re.sub(r"\s+", " ", tm.group(1)).strip()[:300]
        dm = re.search(
            r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)',
            html,
            re.I,
        ) or re.search(
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']description["\']',
            html,
            re.I,
        )
        if dm:
            page_description = dm.group(1).strip()[:500]
        hm = re.search(r"<h1[^>]*>([^<]{3,200})</h1>", html, re.I)
        page_h1 = re.sub(r"\s+", " ", hm.group(1)).strip() if hm else ""
        og_site = re.search(
            r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']+)',
            html,
            re.I,
        )
        og_title = re.search(
            r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)',
            html,
            re.I,
        )
        page_snippet = re.sub(r"<[^>]+>", " ", html[:12000])
        page_snippet = re.sub(r"\s+", " ", page_snippet).strip()[:600]
    else:
        page_h1 = ""
        page_snippet = ""
        og_site = None
        og_title = None
    context["page_title"] = page_title
    context["page_description"] = page_description
    context["domain_profile"] = "education" if institutional else "standard"

    return {
        "tool": "headers",
        "severity": "INFO" if not findings else "MEDIUM",
        "title": "Security headers analysis",
        "detail": f"Checked {len(SECURITY_HEADERS)} security headers",
        "raw": {
            "headers": {k: raw_headers[k] for k in list(raw_headers)[:30]},
            "server": server,
            "x_powered_by": powered,
            "page_title": page_title,
            "page_description": page_description,
            "page_h1": page_h1 if resp else "",
            "og_site_name": og_site.group(1).strip()[:120] if resp and og_site else "",
            "og_title": og_title.group(1).strip()[:200] if resp and og_title else "",
            "page_snippet": page_snippet if resp else "",
            "domain_profile": "education" if institutional else "standard",
            "final_url": str(resp.url) if resp else None,
            "status_code": resp.status_code if resp else None,
        },
        "findings": findings,
        "missing_count": len(findings),
    }
