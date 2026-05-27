import re
import socket
import dns.resolver
from urllib.parse import urlparse

import httpx
import requests

# Common subdomain wordlist for brute forcing
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "blog", "api", "dev", "staging", "test",
    "app", "portal", "secure", "vpn", "cdn", "static", "assets", "img", "images",
    "m", "mobile", "shop", "store", "support", "help", "docs", "wiki", "forum",
    "community", "news", "blog", "dashboard", "panel", "console", "manage",
    "email", "smtp", "pop", "imap", "ns1", "ns2", "dns", "mx", "www2", "www1",
    "webmail", "calendar", "drive", "files", "cloud", "git", "svn", "jenkins",
    "jira", "confluence", "sonarqube", "nexus", "artifactory", "grafana",
    "kibana", "elasticsearch", "prometheus", "monitoring", "logs", "metrics",
    "auth", "login", "sso", "oauth", "identity", "account", "user", "users",
    "billing", "payment", "checkout", "cart", "order", "orders", "product",
    "products", "catalog", "search", "analytics", "tracking", "pixel", "beacon",
    "ads", "ad", "marketing", "promo", "promo1", "promo2", "promo3", "promo4",
    "beta", "alpha", "demo", "sandbox", "lab", "labs", "experimental", "research",
    "internal", "private", "intranet", "extranet", "partner", "partners", "vendor",
    "suppliers", "clients", "customer", "customers", "member", "members",
]

def resolve_subdomain(subdomain: str) -> dict:
    """Resolve a subdomain to get IP and status."""
    result = {
        "subdomain": subdomain,
        "ip": "",
        "status": "unresolved",
        "title": "",
        "http_status": None,
    }
    
    try:
        # DNS resolution
        answers = dns.resolver.resolve(subdomain, 'A')
        if answers:
            result["ip"] = str(answers[0])
            result["status"] = "resolved"
            
            # Try HTTP check
            try:
                resp = httpx.get(f"https://{subdomain}", timeout=5, follow_redirects=True)
                result["http_status"] = resp.status_code
                if resp.status_code == 200:
                    # Extract title
                    title_match = re.search(r'<title>([^<]+)</title>', resp.text, re.IGNORECASE)
                    if title_match:
                        result["title"] = title_match.group(1).strip()[:100]
            except Exception:
                pass
    except Exception:
        pass
    
    return result

def run(domain: str, context: dict) -> dict:
    domain = urlparse(domain).hostname if "://" in domain else domain.strip().lower()
    subdomains = []
    hidden_links = []
    findings = []

    # Method 1: Certificate Transparency (crt.sh)
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
                        subdomains.append({"subdomain": sub, "ip": "", "status": "ct_found", "title": ""})
    except Exception:
        pass

    # Method 2: DNS brute force (limited to first 50 common subdomains)
    seen_subdomains = {s["subdomain"] for s in subdomains}
    brute_force_results = []
    
    for common in COMMON_SUBDOMAINS[:50]:
        subdomain = f"{common}.{domain}"
        if subdomain not in seen_subdomains:
            result = resolve_subdomain(subdomain)
            if result["status"] == "resolved":
                brute_force_results.append(result)
                seen_subdomains.add(subdomain)
    
    subdomains.extend(brute_force_results)

    # Method 3: Resolve all discovered subdomains
    resolved_subdomains = []
    for sub in subdomains:
        if sub["status"] == "ct_found":
            resolved = resolve_subdomain(sub["subdomain"])
            resolved_subdomains.append(resolved)
        else:
            resolved_subdomains.append(sub)
    
    subdomains = resolved_subdomains

    # Method 4: Check robots.txt and sitemap.xml for hidden links
    base = f"https://{domain}"
    for path in ("/robots.txt", "/sitemap.xml"):
        try:
            resp = httpx.get(base + path, timeout=8, follow_redirects=True)
            if resp.status_code == 200:
                urls = re.findall(r"https?://[^\s<>\"']+", resp.text)
                hidden_links.extend([{"source": path, "url": u[:300]} for u in urls[:20]])
        except Exception:
            continue

    # Generate findings
    active_subdomains = [s for s in subdomains if s["status"] == "resolved"]
    
    if len(active_subdomains) > 20:
        findings.append({
            "severity": "MEDIUM",
            "name": f"Large attack surface: {len(active_subdomains)} active subdomains",
            "explanation": f"Many subdomains are accessible, increasing the attack surface.",
            "recommendation": "Review subdomains and ensure only necessary ones are publicly accessible."
        })
    
    # Check for sensitive subdomains
    sensitive_keywords = ["admin", "dev", "staging", "test", "internal", "private", "vpn", "ftp"]
    for sub in active_subdomains:
        subdomain = sub["subdomain"].lower()
        if any(keyword in subdomain for keyword in sensitive_keywords):
            findings.append({
                "severity": "HIGH",
                "name": f"Sensitive subdomain exposed: {subdomain}",
                "explanation": f"A potentially sensitive subdomain ({subdomain}) is publicly accessible.",
                "recommendation": "Ensure this subdomain is properly secured or restricted to internal access."
            })

    context["subdomains"] = subdomains
    return {
        "tool": "subdomains",
        "severity": "INFO",
        "title": "Deep subdomain discovery",
        "detail": f"{len(active_subdomains)} active subdomains",
        "summary": f"Found {len(subdomains)} subdomains via certificate transparency and DNS enumeration",
        "raw": {
            "subdomains": subdomains[:100],
            "active_count": len(active_subdomains),
            "hidden_links": hidden_links
        },
        "findings": findings,
    }
