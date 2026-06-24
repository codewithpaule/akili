import re
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from http_client import get_sync_client

from tools.page_verify import (
    content_confirms_path,
    path_exists,
    probe_hit_from_response,
)

PROBES = [
    ("/robots.txt", "INFO"),
    ("/sitemap.xml", "INFO"),
    ("/sitemap_index.xml", "INFO"),
    ("/.well-known/security.txt", "INFO"),
    ("/.well-known/assetlinks.json", "INFO"),
    ("/.well-known/apple-app-site-association", "INFO"),
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

ADMIN_PATH_MARKERS = (
    "admin", "dashboard", "wp-admin", "manager", "cpanel", "login", "signin",
)


def _fetch_probe(client, probe_url: str) -> dict:
    headers = {
        "User-Agent": "AKILI-Deep-Scan/2.0",
        "Range": "bytes=0-4095",
    }
    resp = client.get(probe_url, headers=headers, follow_redirects=True)
    hit = probe_hit_from_response(resp)
    try:
        ct = (hit.get("content_type") or "").lower()
        if hit.get("status") in (200, 206) and "text/html" in ct:
            resp2 = client.get(probe_url, headers={"User-Agent": "AKILI-Deep-Scan/2.0"}, follow_redirects=True)
            hit = probe_hit_from_response(resp2, text_limit=20000)
    except Exception:
        pass
    return hit


def _miss_signatures(client, base_root: str) -> dict[str, list[dict]]:
    categories = {
        "dotfile": f"/.akili-miss-{uuid.uuid4()}",
        "phpfile": f"/akili-miss-{uuid.uuid4()}.php",
        "directory": f"/akili-miss-{uuid.uuid4()}/",
        "plainfile": f"/akili-miss-{uuid.uuid4()}.txt",
    }
    result: dict[str, list[dict]] = {k: [] for k in categories}
    for category, path in categories.items():
        url = urljoin(base_root, path.lstrip("/"))
        try:
            result[category].append(_fetch_probe(client, url))
        except Exception:
            pass
    return result


def _category_for_path(path: str) -> str:
    p = path.lower()
    if p.startswith("/.") or any(
        p.endswith(ext) for ext in (
            ".env", ".env.local", ".env.production", ".env.prod", ".env.dev",
            ".gitignore", ".htaccess", ".htpasswd", ".npmrc", ".pypirc",
            ".dockercfg", ".gitattributes",
        )
    ):
        return "dotfile"
    if p.endswith(".php"):
        return "phpfile"
    if p.endswith("/") or ("." not in p.split("/")[-1] and not p.endswith("/")):
        return "directory"
    return "plainfile"


def _verification_method(path: str, hit: dict, ai_verified: bool = False) -> str:
    if ai_verified:
        return "ai_verified"
    lower = path.lower()
    if any(m in lower for m in ADMIN_PATH_MARKERS):
        ct = (hit.get("content_type") or "").lower()
        if "text/html" in ct:
            return "login_page"
    if any(lower.endswith(ext) for ext in (".zip", ".tar", ".gz", ".tgz")):
        return "content_type_match"
    return "content_match"


def _finding_explanation(path: str, verification_method: str) -> str:
    if verification_method == "ai_verified":
        return (
            f"The path {path} was found and independently verified by AI content analysis "
            f"as a real resource, not a custom error page."
        )
    if verification_method == "login_page":
        return (
            f"The path {path} is accessible and returned what appears to be a login page or admin panel. "
            f"This path should not be publicly accessible without authentication. "
            f"Verify whether this is intentional and ensure it is properly protected."
        )
    if verification_method == "content_type_match":
        return (
            f"The path {path} returned a binary response with the expected content type for this file type. "
            f"This was confirmed across multiple verification checks."
        )
    return (
        f"The path {path} returned content that looks like the real file. "
        f"The response contained specific markers expected in this file type. "
        f"This was confirmed across multiple verification checks."
    )


def _ai_verify_finding(path: str, risk: str, hit: dict) -> bool:
    content_type = (hit.get("content_type") or "").lower()
    text_sample = (hit.get("text") or "")[:3000]

    if "text/html" not in content_type and "html" not in text_sample[:100].lower():
        return True

    system = (
        "You are a security analyst verifying whether an HTTP response is a real sensitive file "
        "or a custom error page. You will receive the requested path and the response body. "
        "Reply only with valid JSON: {\"real\": true|false, \"reason\": \"one sentence\"}"
    )
    user = (
        f"Requested path: {path}\n"
        f"HTTP Content-Type: {content_type}\n"
        f"Response body (first 3000 chars):\n{text_sample}"
    )

    try:
        from llm import ask_llm
        result, _ = ask_llm(system, user, max_tokens=400)
        if isinstance(result, dict):
            return bool(result.get("real", False))
    except Exception:
        pass
    return False


def _probe_one(client, base_root: str, path: str, risk: str, misses: dict[str, list[dict]]) -> dict:
    probe_url = urljoin(base_root, path.lstrip("/"))
    category = _category_for_path(path)
    category_misses = misses.get(category, [])
    try:
        hit = _fetch_probe(client, probe_url)
        status = hit["status"]
        confirmed_existing = path_exists(path, hit, category_misses)
        verification_method = ""
        if confirmed_existing and risk in ("CRITICAL", "HIGH"):
            ct = (hit.get("content_type") or "").lower()
            sensitive_paths = (
                ".env", ".git/config", "wp-config", ".aws/", ".ssh/",
                ".sql", "credentials.json", "service-account",
            )
            needs_ai_check = "text/html" in ct and any(s in path.lower() for s in sensitive_paths)
            if needs_ai_check:
                confirmed_existing = _ai_verify_finding(path, risk, hit)
                if confirmed_existing:
                    verification_method = "ai_verified"
        if confirmed_existing and not verification_method:
            verification_method = _verification_method(path, hit)
        return {
            "path": path,
            "status": status,
            "accessible": confirmed_existing,
            "risk": risk,
            "final_url": hit.get("final_url", ""),
            "content_verified": confirmed_existing,
            "verification_method": verification_method,
            "hit": hit,
        }
    except Exception:
        return {"path": path, "status": 0, "accessible": False, "risk": risk}


def run(url: str, context: dict) -> dict:
    parsed = urlparse(url)
    base_root = f"{parsed.scheme}://{parsed.netloc}/"
    findings = []
    confirmed = []
    attempted = []

    try:
        client = get_sync_client()
        misses = _miss_signatures(client, base_root)
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {
                pool.submit(_probe_one, client, base_root, path, risk, misses): (path, risk)
                for path, risk in PROBES
            }
            for fut in as_completed(futures):
                entry = fut.result()
                attempted.append({k: v for k, v in entry.items() if k != "hit"})
                if entry.get("accessible"):
                    confirmed.append({k: v for k, v in entry.items() if k != "hit"})
                if entry.get("accessible") and entry.get("risk") in ("CRITICAL", "HIGH"):
                    vm = entry.get("verification_method") or "content_match"
                    findings.append({
                        "severity": entry["risk"],
                        "name": f"Exposed path: {entry['path']}",
                        "explanation": _finding_explanation(entry["path"], vm),
                        "recommendation": "Remove or restrict access to sensitive files immediately.",
                        "url": entry.get("final_url") or urljoin(base_root, entry["path"].lstrip("/")),
                        "verification_method": vm,
                    })
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
        "raw": {"probes": confirmed, "attempted": attempted, "attempted_count": len(attempted)},
        "findings": findings,
    }
