import html
import ipaddress
import re
import socket
from urllib.parse import urlparse

from fastapi import HTTPException

URL_MAX_LEN = 500
NAME_MAX_LEN = 100
KEYWORDS_MAX_LEN = 200
EMAIL_MAX_LEN = 254
DOMAIN_MAX_LEN = 253
ORG_MAX_LEN = 200
MAX_BODY_BYTES = 1_000_000

BLOCKED_HOSTNAMES = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"}

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def sanitize_text(text: str, max_len: int) -> str:
    if not text:
        return ""
    cleaned = html.unescape(text.strip())
    cleaned = re.sub(r"<[^>]+>", "", cleaned)
    cleaned = re.sub(r"[^\w\s\-.,@#&/'\"():+]", "", cleaned)
    return cleaned[:max_len]


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in PRIVATE_NETWORKS:
        if addr in net:
            return True
    return addr.is_private or addr.is_loopback or addr.is_link_local


def is_private_ip_address(ip_str: str) -> bool:
    return _is_private_ip(ip_str.strip())


def _hostname_blocked(hostname: str) -> bool:
    h = hostname.lower().strip(".")
    if h in BLOCKED_HOSTNAMES or h.endswith(".local") or h.endswith(".internal"):
        return True
    if re.match(r"^(127|10|192\.168|172\.(1[6-9]|2\d|3[01]))\.", h):
        return True
    return False


def resolve_and_check_host(hostname: str):
    if _hostname_blocked(hostname):
        raise HTTPException(400, "Target hostname is not allowed (private/internal).")
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise HTTPException(400, "Could not resolve hostname.")
    for info in infos:
        if _is_private_ip(info[4][0]):
            raise HTTPException(400, "Target resolves to a private/internal IP (SSRF blocked).")


def validate_url(url: str) -> str:
    if not url or len(url) > URL_MAX_LEN:
        raise HTTPException(400, f"URL must be 1–{URL_MAX_LEN} characters.")
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(400, "Invalid URL.")
    resolve_and_check_host(parsed.hostname)
    return url


def validate_domain(domain: str) -> str:
    domain = sanitize_text(domain.replace("https://", "").replace("http://", "").split("/")[0], DOMAIN_MAX_LEN)
    if not domain or "." not in domain:
        raise HTTPException(400, "Invalid domain.")
    resolve_and_check_host(domain)
    return domain


def validate_public_ip(ip: str) -> str:
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address.")
    if _is_private_ip(ip):
        raise HTTPException(
            400,
            "Private IPs can only be scanned using the AKILI Local Agent (coming soon).",
        )
    return str(addr)


def validate_person(name: str, keywords: str = "") -> tuple[str, str]:
    name = sanitize_text(name, NAME_MAX_LEN)
    keywords = sanitize_text(keywords, KEYWORDS_MAX_LEN)
    if len(name) < 2:
        raise HTTPException(400, "Name must be at least 2 characters.")
    return name, keywords


def validate_email(email: str) -> str:
    email = sanitize_text(email, EMAIL_MAX_LEN).lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise HTTPException(400, "Invalid email format.")
    return email


def validate_org(name: str, domain: str = "") -> tuple[str, str]:
    name = sanitize_text(name, ORG_MAX_LEN)
    domain = sanitize_text(domain, DOMAIN_MAX_LEN) if domain else ""
    if not name and not domain:
        raise HTTPException(400, "Organization name or domain required.")
    if domain:
        domain = validate_domain(domain)
    return name, domain


def validate_company(name: str, domain: str = "") -> tuple[str, str]:
    return validate_org(name, domain)
