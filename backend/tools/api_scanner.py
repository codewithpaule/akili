"""Simple API scanner: exercise common HTTP methods against a target URL.

This is intentionally lightweight and safe: POST/PUT/PATCH requests use a
non-destructive JSON payload and short timeouts. The route that calls this
tool should ensure the caller is authorized and the target is allowed.
"""
import json
import hashlib
import difflib
import requests
from typing import Dict, Any, List, Optional

COMMON_METHODS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]


def _short_preview(text: str, limit: int = 2000) -> str:
    return (text or "")[:limit]


def _hash_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()


def _diff_text(a: str, b: str, max_lines: int = 40) -> List[str]:
    a_lines = a.splitlines()[:max_lines]
    b_lines = b.splitlines()[:max_lines]
    return list(difflib.unified_diff(a_lines, b_lines, fromfile="base", tofile="other", lineterm=""))


def scan_api(
    target: str,
    methods: Optional[List[str]] = None,
    headers: Optional[Dict[str, str]] = None,
    form_payload: Optional[Dict[str, Any]] = None,
    auth: Optional[Dict[str, str]] = None,
    timeout: int = 8,
    diff: bool = True,
) -> Dict[str, Any]:
    methods = [m.upper() for m in (methods or COMMON_METHODS)]
    out = {"target": target, "results": [], "diffs": []}
    session = requests.Session()
    default_headers = {"User-Agent": "Akili-API-Scanner/1.0"}
    if headers:
        default_headers.update(headers)

    # Prepare auth if provided
    requests_auth = None
    if auth:
        typ = (auth.get("type") or "").lower()
        if typ == "basic" and auth.get("username") is not None:
            requests_auth = (auth.get("username"), auth.get("password", ""))

    responses = {}
    for m in methods:
        if m not in COMMON_METHODS:
            out["results"].append({"method": m, "error": "unsupported method"})
            continue
        try:
            req_headers = dict(default_headers)
            data = None
            json_body = None
            if m in ("POST", "PUT", "PATCH"):
                if form_payload:
                    req_headers["Content-Type"] = "application/x-www-form-urlencoded"
                    data = form_payload
                    resp = session.request(m, target, headers=req_headers, data=data, auth=requests_auth, timeout=timeout, allow_redirects=True)
                else:
                    req_headers["Content-Type"] = "application/json"
                    json_body = {"akili_scan_test": True}
                    resp = session.request(m, target, headers=req_headers, json=json_body, auth=requests_auth, timeout=timeout, allow_redirects=True)
            else:
                resp = session.request(m, target, headers=req_headers, auth=requests_auth, timeout=timeout, allow_redirects=True)

            text = resp.text or ""
            preview = _short_preview(text)
            h = _hash_text(preview)
            record = {
                "method": m,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_preview": preview,
                "body_hash": h,
                "ok": resp.ok,
            }
            out["results"].append(record)
            responses[m] = record
        except Exception as e:
            out["results"].append({"method": m, "error": str(e)})

    # Simple response diffing against GET if requested
    if diff and "GET" in responses:
        base = responses["GET"]["body_preview"]
        for m, rec in responses.items():
            if m == "GET":
                continue
            if rec.get("body_hash") != responses["GET"].get("body_hash"):
                d = _diff_text(base, rec.get("body_preview", ""))
                out["diffs"].append({"method": m, "diff": d})
    return out
