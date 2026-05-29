"""Shared HTTP probe verification — detect soft-404 / custom error pages."""

from __future__ import annotations

import difflib
import hashlib
import re
from urllib.parse import urlparse

MISSING_PAGE_RE = re.compile(
    r"\b(404|not found|page not found|does not exist|could not be found|"
    r"file not found|resource not found|nothing here|no such file|"
    r"page you are looking for|we can't find|unable to find)\b",
    re.I,
)

SENSITIVE_HTML_PATHS = (
    ".env",
    ".git",
    "wp-config",
    ".sql",
    "phpinfo",
    ".htpasswd",
    "credentials",
    "secrets.json",
    "backup.zip",
    "backup.sql",
    "actuator/env",
)


def normalize_body_text(text: str, *, limit: int = 2048) -> str:
    normalized = re.sub(r"\s+", " ", (text or "")).strip().lower()
    normalized = re.sub(r"/[a-z0-9_.~:-]*akili-miss-[a-f0-9-]+[a-z0-9_.~:-]*", "/akili-miss", normalized)
    normalized = re.sub(r"\bakili-miss-[a-f0-9-]+\b", "akili-miss", normalized)
    return normalized[:limit]


def body_hash(text: str) -> str:
    return hashlib.sha256(normalize_body_text(text).encode("utf-8", "ignore")).hexdigest()


def extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip().lower()[:160]


def looks_like_missing_page(html: str) -> bool:
    text = re.sub(r"\s+", " ", (html or "").lower())
    return bool(MISSING_PAGE_RE.search(text[:12000]))


def path_stripped_after_redirect(requested_path: str, final_url: str) -> bool:
    """True when the server dropped the sensitive path segment (e.g. /.env → /)."""
    req = (requested_path or "").strip().lower().rstrip("/") or "/"
    try:
        final_path = (urlparse(final_url or "").path or "/").lower().rstrip("/") or "/"
    except Exception:
        return False
    if req == final_path:
        return False
    # Homepage or generic fallback after requesting a secret path
    if req not in ("/", "") and final_path in ("/", ""):
        return True

    req_leaf = req.rsplit("/", 1)[-1]
    if req_leaf and req_leaf not in (".", "") and req_leaf not in final_path:
        return True
    return False


def looks_like_custom_miss(hit: dict, misses: list[dict]) -> bool:
    text = (hit.get("text") or "").lower()
    if looks_like_missing_page(text):
        return True
    if not misses:
        return False
    for miss in misses:
        try:
            if hit.get("status") != miss.get("status"):
                continue
            if hit.get("location") and hit.get("location") == miss.get("location"):
                return True
            same_title = hit.get("title") and hit.get("title") == miss.get("title")
            same_hash = hit.get("hash") == miss.get("hash")
            similar_length = abs(hit.get("content_length", 0) - miss.get("content_length", 0)) <= 80
            if same_hash or (same_title and similar_length):
                return True
            h_txt = (hit.get("text") or "").strip()
            m_txt = (miss.get("text") or "").strip()
            if h_txt and m_txt:
                ratio = difflib.SequenceMatcher(None, h_txt[:2048], m_txt[:2048]).ratio()
                if ratio > 0.85:
                    return True
        except Exception:
            continue
    return False


def content_confirms_path(path: str, hit: dict) -> bool:
    text = (hit.get("text") or "").lower()
    content_type = (hit.get("content_type") or "").lower()
    lower_path = path.lower()

    if any(k in lower_path for k in SENSITIVE_HTML_PATHS):
        if "text/html" in content_type or "<html" in text[:800] or "<!doctype html" in text[:800]:
            return False
        if looks_like_missing_page(text):
            return False

    checks = {
        ".env": ("app_key", "database_url", "db_password", "secret_key", "aws_access_key", "db_host", "mail_host"),
        ".git/config": ("[core]", "[remote", "repositoryformatversion"),
        ".git/head": ("ref: refs/",),
        ".git/index": ("dirc",),
        "wp-config": ("db_name", "db_user", "wordpress", "wp_"),
        ".sql": ("create table", "insert into", "-- mysql", "dump"),
        "phpinfo": ("php version", "phpinfo()", "configuration"),
        "package.json": ('"dependencies"', '"scripts"', '"devdependencies"'),
        "composer.json": ('"require"', '"autoload"'),
        "requirements.txt": ("==", ">=", "django", "flask", "requests"),
        ".htpasswd": (":$apr1$", ":$2y$", ":$2a$",),
    }
    for key, needles in checks.items():
        if key in lower_path:
            return any(n in text for n in needles)
    if lower_path.endswith((".zip", ".tar", ".gz", ".tgz")):
        return content_type in {
            "application/zip",
            "application/x-tar",
            "application/gzip",
            "application/octet-stream",
        }
    if lower_path.endswith((".json", ".yml", ".yaml", ".xml", ".txt", ".lock", ".log")):
        return bool(text.strip()) and "text/html" not in content_type and not looks_like_missing_page(text)
    if lower_path.endswith((".php",)):
        return not looks_like_missing_page(text) and "text/html" not in content_type
    return not looks_like_missing_page(text)


def probe_hit_from_response(resp, *, text_limit: int = 12000) -> dict:
    text = (resp.text or "")[:text_limit]
    return {
        "status": resp.status_code,
        "location": resp.headers.get("location", ""),
        "final_url": str(resp.url),
        "content_type": (resp.headers.get("content-type") or "").split(";")[0].lower(),
        "content_length": int(resp.headers.get("content-length") or len(resp.content or b"") or 0),
        "title": extract_title(text),
        "hash": body_hash(text),
        "text": text,
    }


def path_exists(
    path: str,
    hit: dict,
    misses: list[dict],
    *,
    require_content: bool = True,
) -> bool:
    """Return True only when HTTP success looks like a real resource, not a soft 404."""
    status = hit.get("status")
    if status not in (200, 206):
        return False
    if path_stripped_after_redirect(path, hit.get("final_url") or hit.get("location") or ""):
        return False
    if looks_like_custom_miss(hit, misses):
        return False
    if require_content and not content_confirms_path(path, hit):
        return False
    return True
