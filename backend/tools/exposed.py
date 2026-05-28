import hashlib
import re
import uuid
from urllib.parse import urljoin, urlparse

import httpx

PROBES = [
    # Discovery and policy files
    ("/robots.txt", "INFO"),
    ("/sitemap.xml", "INFO"),
    ("/sitemap_index.xml", "INFO"),
    ("/.well-known/security.txt", "INFO"),
    ("/.well-known/assetlinks.json", "INFO"),
    ("/.well-known/apple-app-site-association", "INFO"),

    # Admin, login, and control panels
    ("/admin", "HIGH"),
    ("/admin/", "HIGH"),
    ("/admin/login", "HIGH"),
    ("/admin.php", "HIGH"),
    ("/administrator", "HIGH"),
    ("/administrator/", "HIGH"),
    ("/login", "MEDIUM"),
    ("/signin", "MEDIUM"),
    ("/dashboard", "MEDIUM"),
    ("/manage", "HIGH"),
    ("/manager", "HIGH"),
    ("/controlpanel", "HIGH"),
    ("/cpanel", "HIGH"),
    ("/whm", "HIGH"),
    ("/plesk", "HIGH"),
    ("/webmail", "MEDIUM"),
    ("/user/login", "MEDIUM"),
    ("/account/login", "MEDIUM"),

    # CMS and application admin paths
    ("/wp-admin", "HIGH"),
    ("/wp-login.php", "HIGH"),
    ("/xmlrpc.php", "MEDIUM"),
    ("/wp-config.php", "CRITICAL"),
    ("/wp-config.php.bak", "CRITICAL"),
    ("/wp-config.php.save", "CRITICAL"),
    ("/wp-content/debug.log", "HIGH"),
    ("/joomla/administrator", "HIGH"),
    ("/drupal/user/login", "MEDIUM"),
    ("/magento/admin", "HIGH"),
    ("/typo3", "HIGH"),

    # Secrets, environment, and cloud credentials
    ("/.env", "CRITICAL"),
    ("/.env.local", "CRITICAL"),
    ("/.env.production", "CRITICAL"),
    ("/.env.prod", "CRITICAL"),
    ("/.env.dev", "CRITICAL"),
    ("/.env.example", "HIGH"),
    ("/config.php", "CRITICAL"),
    ("/config.json", "HIGH"),
    ("/config.yml", "HIGH"),
    ("/config.yaml", "HIGH"),
    ("/settings.py", "CRITICAL"),
    ("/local_settings.py", "CRITICAL"),
    ("/database.yml", "CRITICAL"),
    ("/credentials.json", "CRITICAL"),
    ("/secrets.json", "CRITICAL"),
    ("/service-account.json", "CRITICAL"),
    ("/firebase.json", "MEDIUM"),
    ("/.npmrc", "CRITICAL"),
    ("/.pypirc", "CRITICAL"),
    ("/.dockercfg", "CRITICAL"),
    ("/.docker/config.json", "CRITICAL"),
    ("/.aws/credentials", "CRITICAL"),
    ("/.aws/config", "CRITICAL"),
    ("/.ssh/id_rsa", "CRITICAL"),
    ("/.ssh/id_ed25519", "CRITICAL"),

    # Source control and project metadata
    ("/.git", "HIGH"),
    ("/.git/", "HIGH"),
    ("/.git/HEAD", "HIGH"),
    ("/.git/config", "CRITICAL"),
    ("/.git/index", "CRITICAL"),
    ("/.svn/entries", "HIGH"),
    ("/.hg", "HIGH"),
    ("/.bzr", "HIGH"),
    ("/.gitignore", "MEDIUM"),
    ("/.gitattributes", "MEDIUM"),
    ("/composer.json", "MEDIUM"),
    ("/composer.lock", "MEDIUM"),
    ("/package.json", "MEDIUM"),
    ("/package-lock.json", "MEDIUM"),
    ("/yarn.lock", "MEDIUM"),
    ("/pnpm-lock.yaml", "MEDIUM"),
    ("/requirements.txt", "MEDIUM"),
    ("/Pipfile", "MEDIUM"),
    ("/poetry.lock", "MEDIUM"),
    ("/Gemfile", "MEDIUM"),
    ("/Gemfile.lock", "MEDIUM"),

    # Backups, dumps, and archives
    ("/backup", "HIGH"),
    ("/backup/", "HIGH"),
    ("/backups", "HIGH"),
    ("/backups/", "HIGH"),
    ("/backup.zip", "CRITICAL"),
    ("/backup.tar", "CRITICAL"),
    ("/backup.tar.gz", "CRITICAL"),
    ("/backup.tgz", "CRITICAL"),
    ("/backup.sql", "CRITICAL"),
    ("/database.sql", "CRITICAL"),
    ("/db.sql", "CRITICAL"),
    ("/dump.sql", "CRITICAL"),
    ("/site.zip", "CRITICAL"),
    ("/www.zip", "CRITICAL"),
    ("/public_html.zip", "CRITICAL"),
    ("/htdocs.zip", "CRITICAL"),
    ("/app.zip", "CRITICAL"),
    ("/source.zip", "CRITICAL"),
    ("/old", "MEDIUM"),
    ("/old/", "MEDIUM"),
    ("/bak", "HIGH"),
    ("/bak/", "HIGH"),

    # Debug, health, metrics, and server internals
    ("/phpinfo.php", "HIGH"),
    ("/info.php", "HIGH"),
    ("/test.php", "MEDIUM"),
    ("/debug", "HIGH"),
    ("/debug/", "HIGH"),
    ("/debug/default/view", "CRITICAL"),
    ("/console", "HIGH"),
    ("/actuator", "HIGH"),
    ("/actuator/env", "CRITICAL"),
    ("/actuator/heapdump", "CRITICAL"),
    ("/actuator/health", "MEDIUM"),
    ("/actuator/metrics", "HIGH"),
    ("/health", "INFO"),
    ("/status", "INFO"),
    ("/metrics", "HIGH"),
    ("/server-status", "MEDIUM"),
    ("/nginx_status", "MEDIUM"),
    ("/server-info", "MEDIUM"),

    # API documentation and developer surfaces
    ("/api", "MEDIUM"),
    ("/api/", "MEDIUM"),
    ("/api/v1", "MEDIUM"),
    ("/api/v2", "MEDIUM"),
    ("/swagger", "MEDIUM"),
    ("/swagger-ui", "MEDIUM"),
    ("/swagger-ui.html", "MEDIUM"),
    ("/api-docs", "MEDIUM"),
    ("/docs", "MEDIUM"),
    ("/redoc", "MEDIUM"),
    ("/openapi.json", "MEDIUM"),
    ("/graphql", "HIGH"),
    ("/graphiql", "HIGH"),
    ("/playground", "HIGH"),

    # Database and infrastructure consoles
    ("/phpmyadmin", "HIGH"),
    ("/phpMyAdmin", "HIGH"),
    ("/pma", "HIGH"),
    ("/adminer.php", "HIGH"),
    ("/mysql", "HIGH"),
    ("/dbadmin", "HIGH"),
    ("/pgadmin", "HIGH"),
    ("/redis", "HIGH"),
    ("/mongo", "HIGH"),
    ("/mongodb", "HIGH"),
    ("/elasticsearch", "HIGH"),
    ("/solr", "HIGH"),
    ("/kibana", "HIGH"),
    ("/grafana", "HIGH"),
    ("/prometheus", "HIGH"),
    ("/jenkins", "HIGH"),
    ("/webmin", "HIGH"),

    # Logs and local files
    ("/logs", "HIGH"),
    ("/logs/", "HIGH"),
    ("/log", "HIGH"),
    ("/log/", "HIGH"),
    ("/error.log", "HIGH"),
    ("/error_log", "HIGH"),
    ("/access.log", "HIGH"),
    ("/access_log", "HIGH"),
    ("/debug.log", "HIGH"),
    ("/storage/logs/laravel.log", "CRITICAL"),
    ("/var/log/nginx/access.log", "HIGH"),
    ("/.htaccess", "HIGH"),
    ("/.htpasswd", "CRITICAL"),
    ("/web.config", "HIGH"),
    ("/app.config", "HIGH"),
    ("/.DS_Store", "MEDIUM"),
    ("/Thumbs.db", "LOW"),
]


def _fetch_probe(client: httpx.Client, probe_url: str) -> dict:
    headers = {
        "User-Agent": "AKILI-Deep-Scan/1.0",
        "Range": "bytes=0-4095",
    }
    resp = client.get(probe_url, headers=headers)
    text = resp.text[:4096] if resp.text else ""
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip().lower()[:160]
    normalized = re.sub(r"\s+", " ", text).strip().lower()
    normalized = re.sub(r"/[a-z0-9_.~:-]*akili-miss-[a-f0-9-]+[a-z0-9_.~:-]*", "/akili-miss", normalized)
    normalized = re.sub(r"\bakili-miss-[a-f0-9-]+\b", "akili-miss", normalized)
    body_hash = hashlib.sha256(normalized[:2048].encode("utf-8", "ignore")).hexdigest()
    return {
        "status": resp.status_code,
        "location": resp.headers.get("location", ""),
        "content_type": (resp.headers.get("content-type") or "").split(";")[0].lower(),
        "content_length": int(resp.headers.get("content-length") or len(resp.content or b"") or 0),
        "title": title,
        "hash": body_hash,
        "text": text,
    }


def _miss_signatures(client: httpx.Client, base_root: str) -> list[dict]:
    signatures = []
    for suffix in (uuid.uuid4(), uuid.uuid4()):
        miss_url = urljoin(base_root, f"akili-miss-{suffix}.txt")
        try:
            signatures.append(_fetch_probe(client, miss_url))
        except Exception:
            continue
    return signatures


def _looks_like_custom_miss(hit: dict, misses: list[dict]) -> bool:
    text = (hit.get("text") or "").lower()
    if re.search(r"\b(404|not found|page not found|does not exist|could not be found)\b", text):
        return True
    if not misses:
        return False
    for miss in misses:
        if hit["status"] != miss["status"]:
            continue
        if hit.get("location") and hit.get("location") == miss.get("location"):
            return True
        same_title = hit.get("title") and hit.get("title") == miss.get("title")
        same_hash = hit.get("hash") == miss.get("hash")
        similar_length = abs(hit.get("content_length", 0) - miss.get("content_length", 0)) <= 80
        if same_hash or (same_title and similar_length):
            return True
    return False


def _content_confirms_path(path: str, hit: dict) -> bool:
    text = (hit.get("text") or "").lower()
    content_type = hit.get("content_type") or ""
    checks = {
        ".env": ("app_key", "database_url", "db_password", "secret_key", "aws_access_key"),
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
    lower_path = path.lower()
    for key, needles in checks.items():
        if key in lower_path:
            return any(n in text for n in needles)
    if lower_path.endswith((".zip", ".tar", ".gz", ".tgz")):
        return content_type in {"application/zip", "application/x-tar", "application/gzip", "application/octet-stream"}
    if lower_path.endswith((".json", ".yml", ".yaml", ".xml", ".txt", ".lock", ".log")):
        return bool(text.strip()) and "text/html" not in content_type
    return True


def run(url: str, context: dict) -> dict:
    parsed = urlparse(url)
    base_root = f"{parsed.scheme}://{parsed.netloc}/"
    findings = []
    confirmed = []
    attempted = []

    try:
        with httpx.Client(timeout=8.0, follow_redirects=False) as client:
            misses = _miss_signatures(client, base_root)
            for path, risk in PROBES:
                probe_url = urljoin(base_root, path.lstrip("/"))
                try:
                    hit = _fetch_probe(client, probe_url)
                    status = hit["status"]
                    confirmed_existing = (
                        status in (200, 206)
                        and not _looks_like_custom_miss(hit, misses)
                        and _content_confirms_path(path, hit)
                    )
                    entry = {
                        "path": path,
                        "status": status,
                        "accessible": confirmed_existing,
                        "risk": risk,
                    }
                    attempted.append(entry)
                    if confirmed_existing:
                        confirmed.append(entry)
                    if confirmed_existing and risk in ("CRITICAL", "HIGH"):
                        findings.append({
                            "severity": risk,
                            "name": f"Exposed path: {path}",
                            "explanation": f"Path {path} returned HTTP {status} and did not match the site's custom missing-page response.",
                            "recommendation": "Remove or restrict access to sensitive files immediately.",
                            "url": probe_url,
                        })
                except Exception:
                    attempted.append({"path": path, "status": 0, "accessible": False, "risk": risk})
    except Exception as e:
        return {
            "tool": "exposed_files",
            "severity": "INFO",
            "title": "Exposed files probe",
            "detail": str(e)[:100],
            "raw": {"probes": []},
            "findings": [],
        }

    severity = "INFO"
    if any(f["severity"] == "CRITICAL" for f in findings):
        severity = "CRITICAL"
    elif findings:
        severity = "HIGH"

    context["exposed_files"] = confirmed
    return {
        "tool": "exposed_files",
        "severity": severity,
        "title": "Exposed files probe",
        "detail": f"Probed {len(PROBES)} paths; confirmed {len(confirmed)} existing",
        "raw": {"probes": confirmed, "attempted_count": len(attempted)},
        "findings": findings,
    }
