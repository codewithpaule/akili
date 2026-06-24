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

ADMIN_PANEL_PATHS = (
    "admin", "dashboard", "wp-admin", "manager", "cpanel",
    "whm", "plesk", "webmail", "phpmyadmin", "pma", "adminer",
    "pgadmin", "grafana", "kibana", "jenkins", "webmin",
    "swagger", "swagger-ui", "redoc", "graphiql", "playground",
)

STRICT_CONTENT_RULES: dict[str, tuple[str, ...]] = {
    ".env": (
        "app_key=", "database_url=", "db_password=", "secret_key=",
        "aws_access_key", "db_host=", "mail_host=", "db_connection=",
    ),
    ".git/config": ("[core]", "[remote", "repositoryformatversion"),
    ".git/head": ("ref: refs/",),
    ".git/index": ("dirc",),
    "wp-config": ("db_name", "db_user", "wp_"),
    ".sql": ("create table", "insert into", "-- mysql", "dump completed"),
    "phpinfo": ("php version", "phpinfo()", "php_uname"),
    "package.json": ('"dependencies"', '"scripts"', '"devdependencies"'),
    "composer.json": ('"require"', '"autoload"'),
    "requirements.txt": ("==", ">=", "django", "flask", "requests"),
    ".htpasswd": (":$apr1$", ":$2y$", ":$2a$"),
    ".git": ("index", "objects", "refs", "head", "config"),
    "actuator/env": ("activeprofiles", "propertysources", "systemproperties", "spring", "classpath"),
    "actuator/heapdump": ("java", "heap", "class"),
    "actuator/health": ('"status"', '"up"', '"down"', "diskspace", "db"),
    "debug/default/view": ("yii", "exception", "stack trace", "error"),
    "phpmyadmin": ("phpmyadmin", "pma_", "mysql server"),
    "adminer.php": ("adminer", "db server", "database"),
    "storage/logs/laravel.log": ("[error]", "[warning]", "laravel", "exception", "stack trace"),
    "credentials.json": ('"type":', '"project_id":', '"private_key":', '"client_email":'),
    "service-account.json": ('"type":', '"project_id":', '"private_key_id":'),
    "firebase.json": ('"hosting":', '"database":', '"rules":'),
    ".npmrc": ("registry=", "//registry", "_authtoken"),
    ".dockercfg": ('"auths":', '"auth":', '"serveraddress":'),
    ".aws/credentials": ("[default]", "aws_access_key_id", "aws_secret_access_key"),
    ".ssh/id_rsa": ("-----begin", "rsa private key", "openssh private key"),
    ".ssh/id_ed25519": ("-----begin", "openssh private key"),
    "backup.zip": (),
    "backup.sql": ("create table", "insert into", "mysqldump"),
    "database.sql": ("create table", "insert into", "mysqldump"),
}


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
    req = (requested_path or "").strip().lower().rstrip("/") or "/"
    try:
        final_path = (urlparse(final_url or "").path or "/").lower().rstrip("/") or "/"
    except Exception:
        return False
    if req == final_path:
        return False
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
    lower_path = path.lower().lstrip("/")

    if any(lower_path.endswith(ext) for ext in (".zip", ".tar", ".gz", ".tgz")):
        return content_type in {
            "application/zip", "application/x-tar", "application/gzip",
            "application/octet-stream", "application/x-gzip",
        }

    for rule_key, needles in STRICT_CONTENT_RULES.items():
        if rule_key in lower_path:
            if "text/html" in content_type or "<html" in text[:200] or "<!doctype" in text[:200]:
                return False
            if needles:
                return any(n.lower() in text for n in needles)
            return True

    if lower_path.rstrip("/") and "." not in lower_path.split("/")[-1]:
        directory_listing_signals = (
            "index of /", "directory listing", "parent directory",
            "[dir]", "[   ]", "last modified",
        )
        if any(signal in text[:5000] for signal in directory_listing_signals):
            return True
        return False

    if "text/html" in content_type or "<html" in text[:200] or "<!doctype" in text[:200]:
        if looks_like_missing_page(text):
            return False
        if any(lower_path.rstrip("/") in d for d in ADMIN_PANEL_PATHS):
            return not looks_like_missing_page(text)
        return False

    stripped = text.strip()
    if not stripped or len(stripped) < 10:
        return False
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
