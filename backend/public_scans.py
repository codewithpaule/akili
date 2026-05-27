import asyncio
import re
import httpx
import dns.resolver
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from fastapi import HTTPException
from tools.ssl_check import run as ssl_check
from tools.headers import run as headers_check
from tools.fallbacks import check_email_breach
from security import _is_private_ip


# IP-based rate limiting store (in-memory for simplicity)
_ip_rate_limits = {}


def check_ip_rate_limit(ip: str, limit: int = 30) -> bool:
    """Check if IP has exceeded rate limit (30 requests/hour)."""
    now = datetime.utcnow()
    hour_key = now.strftime("%Y-%m-%d-%H")
    
    if ip not in _ip_rate_limits:
        _ip_rate_limits[ip] = {}
    
    if hour_key not in _ip_rate_limits[ip]:
        _ip_rate_limits[ip][hour_key] = 0
    
    if _ip_rate_limits[ip][hour_key] >= limit:
        return False
    
    _ip_rate_limits[ip][hour_key] += 1
    return True


async def check_mx_records(domain: str) -> bool:
    """Check if domain has MX records."""
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except Exception:
        return False


async def check_ssrf_protection(url: str):
    """Block private IPs to prevent SSRF attacks."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL")
    
    if hostname.lower() in {"localhost", "localhost.localdomain"} or _is_private_ip(hostname):
        raise HTTPException(status_code=400, detail="Private IP addresses are not allowed")


async def calculate_grade(headers_result: dict, ssl_result: dict) -> str:
    """Calculate security grade based on findings."""
    score = 100
    
    # Deduct for SSL issues
    if ssl_result.get("severity") == "CRITICAL":
        score -= 30
    elif ssl_result.get("severity") == "HIGH":
        score -= 15
    
    # Deduct for missing headers
    missing_count = headers_result.get("missing_count", 0)
    score -= min(missing_count * 5, 30)
    
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"


async def public_email_scan(email: str) -> dict:
    """Public email scan without authentication."""
    # Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    # Check MX records
    domain = email.split("@")[1]
    mx_valid = await check_mx_records(domain)
    
    # Check breaches
    breach_result = check_email_breach(email)
    breaches = breach_result.get("breaches", [])
    
    return {
        "email": email,
        "valid_format": True,
        "mx_valid": mx_valid,
        "breach_found": breach_result.get("pwned", False),
        "breach_count": len(breaches),
        "breaches": [
            {
                "name": b.get("Name", b.get("name", "Unknown")),
                "date": b.get("BreachDate", b.get("year", "Unknown")),
                "data_exposed": b.get("DataClasses", b.get("exposed_data", [])),
                "source_link": f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name', b.get('name', ''))}"
            }
            for b in breaches
        ],
        "cta": "Sign up for full email investigation"
    }


async def public_website_scan(url: str) -> dict:
    """Public website scan without authentication (shallow checks only)."""
    url = (url or "").strip()
    if url and not re.match(r"^https?://", url, flags=re.I):
        url = f"https://{url.lstrip('/')}"

    # Validate URL
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL")
    
    # Block private IPs
    await check_ssrf_protection(url)
    
    # Run shallow checks only
    context = {}
    headers_result = headers_check(url, context)
    ssl_result = ssl_check(url, context)
    grade = await calculate_grade(headers_result, ssl_result)
    
    # Top 3 findings only
    all_findings = headers_result.get("findings", []) + ssl_result.get("findings", [])
    top_findings = sorted(
        all_findings,
        key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(x.get("severity", "INFO"), 0),
        reverse=True
    )[:3]
    
    ssl_raw = ssl_result.get("raw", {})
    return {
        "url": url,
        "grade": grade,
        "ssl_valid": ssl_result.get("severity") != "CRITICAL",
        "ssl_expiry": ssl_raw.get("days_remaining"),
        "top_findings": top_findings,
        "cta": "Sign up for deep AI-powered scan"
    }
