from urllib.parse import urljoin, urlparse

import httpx

PROBES = [
    ("/robots.txt", "INFO"),
    ("/.env", "CRITICAL"),
    ("/.git/config", "CRITICAL"),
    ("/.git/HEAD", "HIGH"),
    ("/wp-config.php.bak", "CRITICAL"),
    ("/backup.sql", "CRITICAL"),
    ("/phpinfo.php", "HIGH"),
    ("/server-status", "MEDIUM"),
    ("/.well-known/security.txt", "INFO"),
]


def run(url: str, context: dict) -> dict:
    base = url if url.endswith("/") else url + "/"
    parsed = urlparse(url)
    base_root = f"{parsed.scheme}://{parsed.netloc}/"
    findings = []
    exposed = []

    try:
        with httpx.Client(timeout=8.0, follow_redirects=False) as client:
            for path, risk in PROBES:
                probe_url = urljoin(base_root, path.lstrip("/"))
                try:
                    resp = client.head(probe_url)
                    if resp.status_code == 405:
                        resp = client.get(probe_url)
                    status = resp.status_code
                    accessible = status in (200, 206, 403)
                    entry = {
                        "path": path,
                        "status": status,
                        "accessible": accessible and status == 200,
                        "risk": risk,
                    }
                    exposed.append(entry)
                    if status == 200 and risk in ("CRITICAL", "HIGH"):
                        findings.append({
                            "severity": risk,
                            "name": f"Exposed path: {path}",
                            "explanation": f"Path {path} returned HTTP {status} (presence detected, contents not retrieved).",
                            "recommendation": "Remove or restrict access to sensitive files immediately.",
                            "url": probe_url,
                        })
                except Exception:
                    exposed.append({"path": path, "status": 0, "accessible": False, "risk": risk})
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

    context["exposed_files"] = exposed
    return {
        "tool": "exposed_files",
        "severity": severity,
        "title": "Exposed files probe",
        "detail": f"Probed {len(PROBES)} paths",
        "raw": {"probes": exposed},
        "findings": findings,
    }
