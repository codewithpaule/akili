"""Authenticated scanning — credentials never stored or logged."""

from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


def _form_login(client: httpx.Client, url: str, username: str, password: str):
    page = client.get(url)
    soup = BeautifulSoup(page.text, "html.parser")
    form = soup.find("form")
    if not form:
        return None
    form_data = {}
    for inp in form.find_all("input"):
        name = inp.get("name", "")
        itype = inp.get("type", "")
        if itype in ("email", "text") and name:
            form_data[name] = username
        elif itype == "password" and name:
            form_data[name] = password
        elif inp.get("value") and name:
            form_data[name] = inp.get("value")
    action = form.get("action", url)
    if not action.startswith("http"):
        action = urljoin(url, action)
    response = client.post(action, data=form_data)
    if response.status_code in (200, 302, 303):
        return {"type": "cookie", "cookies": dict(client.cookies)}
    return None


def _check_headers(url: str, session_token: dict) -> list:
    findings = []
    try:
        with httpx.Client(timeout=12, cookies=session_token.get("cookies", {})) as client:
            r = client.get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}
        if "strict-transport-security" not in headers:
            findings.append({
                "severity": "MEDIUM",
                "name": "HSTS missing on authenticated area",
                "explanation": "Authenticated responses lack HSTS.",
                "recommendation": "Enable HSTS for all authenticated routes.",
                "category": "Security Headers",
            })
    except Exception:
        pass
    return findings


def _check_csrf(url: str, session_token: dict) -> list:
    findings = []
    try:
        with httpx.Client(timeout=12, cookies=session_token.get("cookies", {})) as client:
            r = client.get(url)
            if 'type="password"' in r.text.lower() and "csrf" not in r.text.lower():
                findings.append({
                    "severity": "HIGH",
                    "name": "Possible missing CSRF on authenticated form",
                    "explanation": "Password form without obvious CSRF token.",
                    "recommendation": "Add CSRF tokens to state-changing forms.",
                    "category": "Form Protection",
                })
    except Exception:
        pass
    return findings


def run_auth_scan(url: str, auth_type: str, credentials: dict, depth: str = "standard") -> dict:
    findings = []
    session_token = None
    login_ok = False

    try:
        with httpx.Client(timeout=15, follow_redirects=True) as client:
            if auth_type == "form":
                session_token = _form_login(
                    client, url,
                    credentials.get("username", ""),
                    credentials.get("password", ""),
                )
            elif auth_type == "basic":
                client.auth = (credentials.get("username", ""), credentials.get("password", ""))
                r = client.get(url)
                session_token = {"type": "basic"} if r.status_code == 200 else None
            elif auth_type == "token":
                hdr = credentials.get("header_name", "Authorization")
                client.headers[hdr] = credentials.get("token", "")
                r = client.get(url)
                session_token = {"type": "token"} if r.status_code == 200 else None
            elif auth_type == "cookie":
                client.cookies.set(
                    credentials.get("cookie_name", "session"),
                    credentials.get("cookie_value", ""),
                )
                r = client.get(url)
                session_token = {"type": "cookie", "cookies": dict(client.cookies)} if r.status_code == 200 else None

            credentials = None

            if session_token:
                login_ok = True
                if session_token.get("cookies"):
                    findings += _check_headers(url, session_token)
                    findings += _check_csrf(url, session_token)
                findings.append({
                    "severity": "INFO",
                    "name": "Session established",
                    "explanation": "Authenticated session was created for scanning.",
                    "recommendation": "Review session timeout and secure cookie flags.",
                    "category": "Session Security",
                })
    finally:
        session_token = None
        credentials = None

    if not login_ok:
        return {"success": False, "error": "Login failed — check credentials and authorization", "findings": []}

    return {
        "success": True,
        "findings": findings,
        "grade": "B" if not any(f["severity"] == "HIGH" for f in findings) else "C",
        "score": 75 if login_ok else 30,
        "summary": "Authenticated scan completed. Credentials were not stored.",
    }


def run(url: str, context: dict) -> dict:
    creds = context.get("auth_credentials", {})
    auth_type = context.get("auth_type", "form")
    depth = context.get("auth_depth", "standard")
    result = run_auth_scan(url, auth_type, creds, depth)
    context["auth_result"] = result
    return {
        "tool": "auth_scan",
        "severity": "INFO" if result.get("success") else "HIGH",
        "title": "Authenticated scan",
        "detail": result.get("summary", result.get("error", "")),
        "summary": result.get("summary", ""),
        "raw": result,
        "findings": result.get("findings", []),
    }
