"""Agentic scan policy and guardrails."""
import re
from urllib.parse import urlparse

# Disallowed patterns or hosts (besides private IPs handled elsewhere)
DISALLOWED_HOST_PATTERNS = [
    r".*example-internal.*",
]


def is_allowed_target(url: str) -> bool:
    """Return True if this URL is allowed for automated agent scanning under policy."""
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if not host:
            return False
        for pat in DISALLOWED_HOST_PATTERNS:
            if re.match(pat, host):
                return False
        return True
    except Exception:
        return False


def extract_domain(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""
