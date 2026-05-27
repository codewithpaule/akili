import inspect
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Generator
from functools import lru_cache
from datetime import datetime, timedelta
from urllib.parse import urlparse

from dotenv import load_dotenv
from groq import Groq

from database import create_session, save_scan
from audit_log import log_audit
from tools import (
    domain_rep,
    email_intel,
    exposed,
    fingerprint,
    headers,
    ip_intel,
    org_scan,
    osint,
    ports,
    ssl_check,
    subdomains,
    vulnerability,
    whois_check,
)
from tools.port_scanner import run_port_scan
from tools.tech_fingerprint import run_tech_fingerprint
from tools.cve_lookup import run_cve_lookup
from tools.link_crawler import run_link_crawler

load_dotenv()
logger = logging.getLogger("akili.agent")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
MAX_ITERATIONS = 12

# Simple in-memory cache for expensive operations
_tool_cache = {}
_cache_ttl = 300  # 5 minutes


def _get_cache_key(tool: str, target: str) -> str:
    """Generate cache key for tool results."""
    return f"{tool}:{target}"


def _get_cached_result(tool: str, target: str) -> Any:
    """Get cached result if available and not expired."""
    key = _get_cache_key(tool, target)
    if key in _tool_cache:
        cached = _tool_cache[key]
        if time.time() - cached["timestamp"] < _cache_ttl:
            return cached["result"]
    return None


def _set_cached_result(tool: str, target: str, result: Any):
    """Cache tool result."""
    key = _get_cache_key(tool, target)
    _tool_cache[key] = {
        "result": result,
        "timestamp": time.time()
    }


BASELINE_TOOLS = {
    "website": ["ssl_check", "headers", "fingerprint", "whois_check", "ports", "port_scanner", "tech_fingerprint", "link_crawler", "cve_lookup"],
    "vulnerability": ["vulnerability", "headers", "tech_fingerprint", "cve_lookup"],
    "subdomains": ["subdomains"],
    "ip": ["ip_intel", "ports", "port_scanner"],
    "organization": ["org_scan"],
    "person": ["osint_person"],
    "company": ["org_scan", "fingerprint", "tech_fingerprint"],
    "email": ["email_intel"],
    "domain": ["domain_rep", "whois_check"],
    "api": ["headers", "fingerprint", "ssl_check", "ports", "tech_fingerprint", "cve_lookup"],
}

TOOL_MAP = {
    "ssl_check": lambda t, c: ssl_check.run(_as_url(t), c),
    "ssl": lambda t, c: ssl_check.run(_as_url(t), c),
    "headers": lambda t, c: headers.run(_as_url(t), c),
    "whois_check": lambda t, c: whois_check.run(_as_url(t), c),
    "whois": lambda t, c: whois_check.run(_as_url(t), c),
    "dns": lambda t, c: whois_check.run_dns_only(_as_url(t), c),
    "ports": lambda t, c: ports.run(_as_url(t) if c.get("module") != "ip" else f"http://{t}", c),
    "fingerprint": lambda t, c: fingerprint.run(_as_url(t), c),
    "exposed_files": lambda t, c: exposed.run(_as_url(t), c),
    "exposed": lambda t, c: exposed.run(_as_url(t), c),
    "vulnerability": lambda t, c: vulnerability.run(_as_url(t), c),
    "subdomains": lambda t, c: subdomains.run(t, c),
    "ip_intel": lambda t, c: ip_intel.run(t, c),
    "org_scan": lambda t, c: org_scan.run(t, c),
    "email_intel": lambda t, c: email_intel.run(t, c),
    "domain_rep": lambda t, c: domain_rep.run(t, c),
    "osint_person": lambda t, c: _osint_person(t, c),
    "nmap": lambda t, c: ports.run(_as_url(t), c),
    "port_scan": lambda t, c: ports.run(_as_url(t), c),
    "port_scanner": lambda t, c: run_port_scan(t if c.get("module") == "ip" else _host_from_target(t), c),
    "tech_fingerprint": lambda t, c: run_tech_fingerprint(_as_url(t), c),
    "cve_lookup": lambda t, c: run_cve_lookup(c.get("technologies", []), c),
    "link_crawler": lambda t, c: run_link_crawler(_as_url(t), c),
}

# Modules that only run baseline tools — no follow-up AI tool picker (avoids nmap on names)
SINGLE_PASS_MODULES = frozenset({"person", "email", "domain", "subdomains"})

TOOL_ALIASES = {
    "nmap": "ports",
    "port_scan": "ports",
    "ssl": "ssl_check",
    "whois": "whois_check",
    "exposed": "exposed_files",
}

NEXT_ACTION_PROMPT = """You are AKILI's senior autonomous cybersecurity triage engine running an authorized assessment.
Your job is to push the scan deeper without wasting a tool call. Read the evidence, identify the riskiest unresolved question, and pick exactly one next tool.

Think like an operator and a defender:
- If exposed services, databases, admin panels, weak TLS, missing headers, leaked files, suspicious domains, stale technologies, or takeover paths appear, choose the tool that can confirm impact or collect better evidence.
- Prefer evidence-rich checks over cosmetic checks.
- Do not repeat tools already used.
- Stop only when every useful tool has run or no remaining tool can add meaningful security evidence.

Available tools: {available_tools}
Already used: {used_tools}

Respond ONLY in valid JSON:
{{"tool": "tool_name", "reason": "one clear sentence explaining the defensive value", "priority": "high|medium|low"}}
Or if complete: {{"done": true, "reason": "all meaningful checks complete"}}"""

FINAL_WEBSITE_PROMPT = """You are a senior cybersecurity analyst preparing a report that should make a real software owner want to patch. Use ONLY the evidence JSON provided.
Produce assessment JSON:
{{"grade":"A-F","score":0-100,"summary":"3 sentences for site owners","site_purpose":"what this website does — university, shop, blog, etc. Use page_title, page_h1, page_description, og fields","legitimacy":"likely_legit|suspicious|unclear","legitimacy_notes":"brief evidence-based note","findings":[{{"severity":"critical|high|medium|low|info","name":"","explanation":"","recommendation":""}}]}}
Rules:
- Actively look for exposed admin/login surfaces, public databases, dangerous ports, missing or weak TLS, missing security headers, old frameworks/CMS/plugins, CVEs tied to detected versions, leaked config/backup files, directory listings, risky CORS, mixed content, insecure cookies, suspicious redirects, weak DNS posture, and excessive attack surface.
- For each finding, explain why it matters to attackers and what the owner should patch or configure.
- Do not soften real high-risk evidence. Use critical/high when internet-exposed management services, databases, known exploitable CVEs, leaked secrets, or takeover paths are supported by evidence.
- .edu / .edu.ng / .gov / university in title → likely_legit unless clear malware/phishing signals.
- Missing security headers alone must NOT yield grade F or score below 55 for institutional sites.
- Do not invent breaches, malware, or scams without evidence in the payload.
- site_purpose must describe the actual organization (e.g. Nigerian university portal), not generic filler.
NEVER include exploit code."""

IP_PROMPT = """You are a senior cybersecurity analyst reviewing public IP intelligence for defensive remediation.
Use ONLY the evidence JSON. Tell the owner what this IP exposes and what to fix first.
Inspect geolocation, ASN/org, reverse DNS, hosted domains/websites, Shodan evidence if present, open ports, service banners, database/remote-admin exposure, and website titles.
Escalate severity when public services commonly used for administration or data stores are open (SSH, Telnet, SMB, RDP, VNC, MySQL, PostgreSQL, Redis, MongoDB), when many ports are exposed, or when hosted websites reveal sensitive systems.
Do not claim compromise without evidence. Do not include exploit code.
Produce JSON:
{{"summary":"2-3 sentences","risk_level":"low|medium|high","hosted_websites_summary":"what websites/domains run on this IP","findings":[{{"severity":"info|low|medium|high","name":"","explanation":"","recommendation":""}}]}}
Use hosted_websites and reverse_dns from evidence. Mention primary website title if present. Recommendations must be concrete patching, firewalling, hardening, or monitoring actions."""

EMAIL_PROMPT = """You are a cybersecurity analyst. From email scan JSON (breaches, MX, disposable), write JSON:
{{"summary":"2-3 sentences","risk_level":"low|medium|high","recommendations":["action1","action2"],"pwned_assessment":"plain explanation if breaches listed"}}
If breaches array is non-empty, state clearly the email was found in data breaches."""

PERSON_PROMPT = """You are a professional due diligence analyst. From public OSINT only, write JSON:
{{"name":"","confidence":0-100,"platforms":{{}},"trust_signals":[],"red_flags":[],"profile_narrative":"2-4 sentences: who they likely are, role, location hints from public sources","age_context":"age range or life-stage ONLY if public evidence (job title, graduation year, news); else \"not enough public data\"","role_hint":"","location_hint":"","ai_summary":"","overall_assessment":"proceed|verify further|insufficient data"}}
Rules:
- Be skeptical with common names and generic social links.
- If GitHub is absent or rejected, say there is no verified developer/GitHub evidence instead of implying the person is a developer.
- If the evidence does not prove the same person across platforms, lower confidence and say "insufficient data" or "verify further".
Never invent private facts. Never make character judgments beyond data."""


def _as_url(target: str) -> str:
    if target.startswith("http"):
        return target
    if re.match(r"^\d+\.\d+\.\d+\.\d+", target):
        return f"http://{target}"
    return f"https://{target}"


def _host_from_target(target: str) -> str:
    url = _as_url(target)
    return urlparse(url).hostname or target


def _osint_person(target: str, context: dict) -> dict:
    parts = target.split("|", 1) if "|" in target else [target, ""]
    name, kw = parts[0].strip(), parts[1].strip() if len(parts) > 1 else ""
    data = osint.run_person_collect(name, kw)
    context["osint"] = data
    # Build a short platforms summary for streaming output (easier verification)
    try:
        plats = []
        for p, info in (data.get("platforms") or {}).items():
            if info and info.get("found"):
                h = info.get("handle") or info.get("url") or ""
                if h:
                    plats.append(f"{p}({h})")
                else:
                    plats.append(p)
        plat_summary = ", ".join(plats)
    except Exception:
        plat_summary = ""
    return {
        "tool": "osint_person",
        "severity": "INFO",
        "title": "Person OSINT",
        "detail": f"{len(data.get('raw_results', []))} results",
        "summary": f"Collected public data for {name}" + (f" — {plat_summary}" if plat_summary else ""),
        "raw": data,
        "findings": [],
    }


def _get_client():
    return Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None


def parse_json_response(text: str) -> dict:
    text = text.strip()
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if m:
        text = m.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m2 = re.search(r"\{[\s\S]*\}", text)
        return json.loads(m2.group()) if m2 else {}


def ask_groq(system: str, user: str, scan_tier: str = "trial", expected_schema: str | None = None) -> dict:
    """Groq → Gemini (free) → rule-based fallback.

    If `scan_tier` == 'premium' then allow ensemble calls to all configured providers.
    """
    from llm import ask_llm
    # Always prefer ensemble across providers to improve reliability; providers without keys are skipped.
    allow_ensemble = True
    data, provider = ask_llm(system, user, allow_ensemble=allow_ensemble, expected_schema=expected_schema)
    if provider != "groq":
        logger.info("LLM provider=%s (ensemble=%s)", provider, allow_ensemble)
    return data


def _email_intel_from_context(context: dict) -> dict:
    if context.get("email_intel"):
        return context["email_intel"]
    for tr in context.get("tool_results", []):
        if tr.get("tool") == "email_intel":
            return tr.get("raw", {})
    return {}


def _build_website_ai_payload(context: dict) -> dict:
    from urllib.parse import urlparse

    host = urlparse(context.get("target", "")).hostname or ""
    payload = {
        "target": context.get("target"),
        "hostname": host,
        "domain_profile": context.get("domain_profile", "standard"),
        "page_title": context.get("page_title", ""),
        "page_description": context.get("page_description", ""),
        "page_h1": "",
        "og_site_name": "",
        "og_title": "",
        "page_snippet": "",
        "ssl": {},
        "whois": {},
        "dns_count": len(context.get("dns_records") or []),
        "technologies": [],
        "open_ports": [],
        "tool_findings": context.get("findings", [])[:20],
    }
    for tr in context.get("tool_results", []):
        raw = tr.get("raw", {})
        tool = tr.get("tool", "")
        if tool == "headers":
            payload["page_title"] = raw.get("page_title") or payload["page_title"]
            payload["page_description"] = raw.get("page_description") or payload["page_description"]
            payload["page_h1"] = raw.get("page_h1", "")
            payload["og_site_name"] = raw.get("og_site_name", "")
            payload["og_title"] = raw.get("og_title", "")
            payload["page_snippet"] = raw.get("page_snippet", "")
            payload["domain_profile"] = raw.get("domain_profile", payload["domain_profile"])
            payload["final_url"] = raw.get("final_url")
        if tool == "ssl_check":
            payload["ssl"] = {k: raw.get(k) for k in ("valid", "issuer", "days_remaining", "subject") if k in raw}
        if tool in ("whois_check", "whois"):
            payload["whois"] = raw.get("whois", {})
        if tool == "fingerprint":
            payload["technologies"] = [
                {"name": t.get("name"), "version": t.get("version")}
                for t in (raw.get("technologies") or [])[:15]
            ]
        if tool == "ports":
            payload["open_ports"] = raw.get("ports", [])[:15]
    if host and (host.endswith(".edu.ng") or ".edu." in host or host.endswith(".edu")):
        payload["domain_profile"] = "academic"
    return payload


def _merge_ip_report(context: dict, ai: dict) -> dict:
    raw = context.get("ip_intel") or {}
    for tr in context.get("tool_results", []):
        if tr.get("tool") == "ip_intel":
            raw = tr.get("raw", raw)
    geo = raw.get("geolocation", {})
    return {
        "scan_type": "ip",
        "target": context.get("target"),
        "ip": raw.get("ip", context.get("target")),
        "summary": ai.get("summary", ""),
        "risk_level": ai.get("risk_level", "low"),
        "hosted_websites_summary": ai.get("hosted_websites_summary", ""),
        "reverse_dns": raw.get("reverse_dns"),
        "geolocation": geo,
        "ports": raw.get("ports", []),
        "hosted_domains": raw.get("hosted_domains", []),
        "hosted_websites": raw.get("hosted_websites", []),
        "primary_website": raw.get("primary_website"),
        "findings": ai.get("findings", context.get("findings", [])),
    }


def _merge_email_report(context: dict, raw: dict, ai: dict) -> dict:
    breaches = raw.get("breaches", [])
    breach_check = raw.get("breach_check", {})
    pwned = raw.get("pwned") or breach_check.get("pwned") or bool(breaches)
    return {
        "scan_type": "email",
        "target": context.get("target"),
        "email": raw.get("email", context.get("target")),
        "pwned": pwned,
        "breach_count": len(breaches),
        "breaches": breaches,
        "breach_source": breach_check.get("source", ""),
        "hibp_configured": bool(os.getenv("HIBP_API_KEY", "").strip()),
        "mx_valid": raw.get("mx_valid"),
        "disposable": raw.get("disposable"),
        "gravatar": raw.get("gravatar"),
        "summary": ai.get("summary", ""),
        "risk_level": ai.get("risk_level", "high" if pwned else "low"),
        "pwned_assessment": ai.get("pwned_assessment", ""),
        "recommendations": ai.get("recommendations", []),
        "findings": context.get("findings", []),
        "ai_summary": ai.get("summary", ""),
    }


_groq_health_cache: dict[str, Any] = {"at": 0.0, "ok": False, "detail": ""}


def check_groq_health(*, force: bool = False) -> tuple[bool, str]:
    if not GROQ_API_KEY:
        return False, "GROQ_API_KEY not set"
    now = time.time()
    if not force and now - _groq_health_cache["at"] < 45:
        return _groq_health_cache["ok"], _groq_health_cache["detail"]
    client = _get_client()
    try:
        client.chat.completions.create(model=GROQ_MODEL, messages=[{"role": "user", "content": "ping"}], max_tokens=5)
        _groq_health_cache.update(at=now, ok=True, detail="")
        return True, ""
    except Exception as e:
        detail = str(e)[:200]
        _groq_health_cache.update(at=now, ok=False, detail=detail)
        return False, detail


TOOL_LABELS = {
    "ssl_check": "SSL certificate",
    "headers": "HTTP security headers",
    "whois_check": "WHOIS & DNS",
    "ports": "open ports",
    "fingerprint": "technology fingerprint",
    "exposed_files": "exposed files",
    "vulnerability": "vulnerability patterns",
    "subdomains": "subdomain discovery",
    "ip_intel": "IP intelligence",
    "org_scan": "organization footprint",
    "email_intel": "email reputation",
    "domain_rep": "domain reputation",
    "osint_person": "person OSINT (web search)",
    "dns": "DNS records",
}


def _tool_label(name: str) -> str:
    return TOOL_LABELS.get(name, name.replace("_", " "))


def _normalize_tech_hint(hint: dict) -> dict:
    version = hint.get("version")
    if version and not isinstance(version, str):
        version = str(version)
    return {
        "name": hint.get("name", "Unknown"),
        "categories": hint.get("categories") or [],
        "version": version,
        "confidence": hint.get("confidence", 75),
        "cves": [],
        "cve_count": 0,
        "cve_severity": "none",
        "cve_source": "none",
    }


def stream_line(kind: str, msg: str) -> str:
    prefix = {
        "AKILI": "[AKILI]",
        "THINK": "[THINK]",
        "PLAN": "[PLAN]",
        "PROGRESS": "[PROGRESS]",
        "TOOL": "[TOOL]",
        "FOUND": "[FOUND]",
        "CRITICAL": "[CRITICAL]",
        "OK": "[OK]",
        "AI": "[AI]",
        "DONE": "[DONE]",
    }.get(kind, "[AKILI]")
    return f"{prefix} {msg}\n"


def _normalize_tool(name: str) -> str:
    if not name:
        return ""
    key = str(name).strip().lower().replace(" ", "_")
    return TOOL_ALIASES.get(key, key)


def run_tool(name: str, target: str, context: dict) -> dict | None:
    name = _normalize_tool(name)
    module = context.get("module", "")
    
    # Check cache for expensive tools
    cacheable_tools = {"ssl_check", "whois_check", "fingerprint", "headers", "ip_intel"}
    if name in cacheable_tools:
        cached = _get_cached_result(name, target)
        if cached:
            context.setdefault("tools_used", []).append(name)
            context.setdefault("tool_results", []).append(cached)
            for f in cached.get("findings", []):
                context.setdefault("findings", []).append(f)
            return cached
    
    allowed = set(get_available_tools(module))
    if allowed and name not in allowed:
        context.setdefault("tools_used", []).append(name)
        return {
            "tool": name,
            "severity": "INFO",
            "title": "Skipped",
            "summary": f"{name} not used for {module} scans",
            "findings": [],
        }
    if name in context.get("tools_used", []):
        return None
    fn = TOOL_MAP.get(name)
    if not fn:
        context.setdefault("tools_used", []).append(name)
        return {
            "tool": name,
            "severity": "INFO",
            "title": "Unknown tool",
            "summary": f"Tool '{name}' is not available",
            "findings": [],
        }
    context.setdefault("tools_used", []).append(name)
    try:
        result = fn(target, context)
        if inspect.iscoroutine(result):
            from tools.async_util import run_async
            result = run_async(result)
        
        # Cache expensive tool results
        if name in cacheable_tools:
            _set_cached_result(name, target, result)
        
        context.setdefault("tool_results", []).append(result)
        for f in result.get("findings", []):
            context.setdefault("findings", []).append(f)
        return result
    except Exception as e:
        return {"tool": name, "severity": "info", "title": "Error", "summary": str(e)[:200], "findings": []}


def get_available_tools(module: str) -> list[str]:
    if module == "person":
        return ["osint_person"]
    base = ["headers", "ssl_check", "whois_check", "dns", "ports", "port_scanner", "fingerprint", "tech_fingerprint", "cve_lookup", "exposed_files", "link_crawler", "vulnerability", "subdomains"]
    if module == "ip":
        return ["ip_intel", "ports", "port_scanner"]
    if module == "email":
        return ["email_intel"]
    if module == "domain":
        return ["domain_rep", "whois_check"]
    if module == "organization":
        return ["org_scan", "subdomains"]
    return base


def _merge_website_report(context: dict, ai: dict) -> dict:
    from urllib.parse import urlparse

    from database import get_score_history, save_score_history

    report = {
        "grade": ai.get("grade", "C"),
        "score": int(ai.get("score", 50)),
        "summary": ai.get("summary", ""),
        "findings": ai.get("findings", context.get("findings", [])),
        "scan_type": context.get("module"),
        "target": context.get("target"),
    }
    header_hints: list[dict] = []
    for tr in context.get("tool_results", []):
        raw = tr.get("raw", {})
        tool = tr.get("tool", "")
        if tool == "ports":
            report["ports"] = raw.get("ports", [])
        if tool == "port_scanner":
            report["port_scan"] = raw
        if tool == "fingerprint":
            techs = raw.get("technologies") or raw.get("tech_stack") or []
            if techs:
                report["tech_stack"] = techs
            report["tech_changes"] = raw.get("tech_changes", context.get("tech_changes", []))
            report["cve_data_source"] = raw.get("cve_data_source", "cve.circl.lu")
        if tool in ("whois_check", "whois", "dns"):
            if raw.get("dns"):
                report["dns"] = raw["dns"]
            if raw.get("whois"):
                report["whois"] = raw["whois"]
        if tool == "exposed_files":
            report["exposed_files"] = raw.get("probes", [])
        if tool == "link_crawler":
            report["crawl"] = raw
            report["interesting_links"] = raw.get("interesting_links", [])
            report["hidden_paths"] = raw.get("hidden_paths", [])
            report["all_links"] = raw.get("all_links", [])
        if tool == "vulnerability":
            report["vulnerability"] = raw
        if tool == "headers":
            report["page_title"] = raw.get("page_title", "")
            report["page_description"] = raw.get("page_description", "")
            report["page_h1"] = raw.get("page_h1", "")
            report["og_site_name"] = raw.get("og_site_name", "")
            report["domain_profile"] = raw.get("domain_profile", "standard")
            srv = raw.get("server") or ""
            if srv:
                header_hints.append({"name": srv.split("/")[0].strip() or srv, "categories": ["Web server"], "version": srv.split("/")[1] if "/" in srv else None})
            powered = raw.get("x_powered_by") or ""
            if powered:
                header_hints.append({"name": powered.split("/")[0].strip() or powered, "categories": ["Framework"], "version": powered.split("/")[1] if "/" in powered else None})

    if context.get("dns_records") and not report.get("dns"):
        report["dns"] = context["dns_records"]
    if header_hints and not report.get("tech_stack"):
        report["tech_stack"] = [_normalize_tech_hint(h) for h in header_hints]
        report["cve_data_source"] = report.get("cve_data_source", "http-headers")

    report["site_purpose"] = ai.get("site_purpose", report.get("site_purpose", ""))
    report["legitimacy"] = ai.get("legitimacy", report.get("legitimacy", "unclear"))
    report["legitimacy_notes"] = ai.get("legitimacy_notes", report.get("legitimacy_notes", ""))
    if not report.get("site_purpose"):
        parts = [
            report.get("page_title"),
            report.get("page_h1"),
            report.get("page_description"),
        ]
        report["site_purpose"] = " — ".join(p for p in parts if p)[:500] or ""
    if report.get("domain_profile") == "academic" and report.get("legitimacy") == "suspicious":
        report["legitimacy"] = "likely_legit"
        report["legitimacy_notes"] = (
            (report.get("legitimacy_notes") or "")
            + " Academic institution domain — flagged as likely legitimate unless you have specific threat intel."
        ).strip()

    if not report.get("tech_stack") and context.get("tech_stack"):
        report["tech_stack"] = context["tech_stack"]
        report["tech_changes"] = context.get("tech_changes", [])
        report["cve_data_source"] = report.get("cve_data_source", "http-fingerprint")

    domain = urlparse(context.get("target", "")).hostname or context.get("domain", "")
    if domain:
        save_score_history(str(uuid.uuid4()), domain, context.get("scan_id", ""), report)
        report["score_history"] = get_score_history(domain)
        prev = report["score_history"][-2]["score"] if len(report.get("score_history", [])) >= 2 else None
        if prev is not None:
            diff = report["score"] - prev
            if diff > 0:
                report["score_message"] = f"Great progress — score up {diff} points since last scan"
            elif diff < 0:
                report["score_message"] = f"Score dropped {abs(diff)} points since last scan — review new findings"
    return report


def _fallback_report(context: dict) -> dict:
    findings = context.get("findings", [])
    crit = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
    high = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
    edu = context.get("domain_profile") == "education"
    penalty = crit * 25 + high * 8 + len([f for f in findings if str(f.get("severity", "")).lower() == "medium"]) * 3
    if edu:
        penalty = int(penalty * 0.5)
    score = max(40 if edu else 20, 90 - penalty)
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"
    return {"grade": grade, "score": score, "summary": "Automated scan completed.", "findings": findings}


def run_agent(
    module: str,
    target: str,
    scan_id: str,
    *,
    lite: bool = False,
    user_id: str = "",
    scan_tier: str = "trial",
) -> Generator[str, None, None]:
    start = time.time()
    create_session(scan_id, module, target)
    context = {
        "module": module,
        "target": target,
        "scan_id": scan_id,
        "findings": [],
        "tools_used": [],
        "tool_results": [],
        "iteration": 0,
    }
    # scan_id available to all tools (e.g. fingerprint snapshots)
    tool_count = 0

    from scan_profile import baseline_tools, profile_for_tier

    prof = profile_for_tier(scan_tier)
    if scan_tier == "guest":
        lite = True
    yield stream_line("AKILI", f"Starting deep {module} assessment… ({prof.get('label', scan_tier)})")
    yield stream_line("THINK", f"Target: {target[:120]}")
    yield stream_line("THINK", prof.get("description", "Running security checks…")[:200])

    baselines = baseline_tools(module, scan_tier) or BASELINE_TOOLS.get(module, ["headers"])
    for i, tool in enumerate(baselines, 1):
        label = _tool_label(tool)
        yield stream_line("PROGRESS", f"Step {i}/{len(baselines)} — now checking {label}…")
        if tool == "osint_person":
            yield stream_line("THINK", "Searching public web & social signals (SerpAPI)…")
        yield stream_line("TOOL", f"Running {_tool_label(tool)}…")
        context["scan_id"] = scan_id
        result = run_tool(tool, target, context)
        tool_count += 1
        if result:
            sev = str(result.get("severity", "info")).upper()
            yield stream_line("OK", f"{_tool_label(tool)} complete")
            yield stream_line("FOUND" if sev not in ("CRITICAL",) else "CRITICAL", result.get("summary", result.get("title", "")))
            for f in result.get("findings", []):
                fs = str(f.get("severity", "INFO")).upper()
                yield stream_line("CRITICAL" if fs == "CRITICAL" else "FOUND", f.get("name", ""))
        else:
            yield stream_line("OK", f"{_tool_label(tool)} — no extra data")

    if module in SINGLE_PASS_MODULES:
        yield stream_line("THINK", "OSINT collection complete — generating person report")
    tier_loops = int(prof.get("max_iterations", 0))
    max_loops = 0 if lite or module in SINGLE_PASS_MODULES else min(MAX_ITERATIONS, tier_loops)
    while context["iteration"] < max_loops:
        context["iteration"] += 1
        allowed_set = set(get_available_tools(module))
        available = [t for t in allowed_set if t not in context["tools_used"]]
        if not available:
            yield stream_line("THINK", "All configured deep tools have run — finishing discovery")
            break
        n_findings = len(context["findings"])
        yield stream_line("THINK", f"Reviewing {n_findings} finding(s) — deciding what to try next…")
        yield stream_line("THINK", "AKILI is thinking…")
        prompt = NEXT_ACTION_PROMPT.format(available_tools=available, used_tools=context["tools_used"])
        decision = ask_groq(prompt, json.dumps({"findings": context["findings"][:15]}), scan_tier, expected_schema="next_action")
        if not decision:
            if available:
                decision = {"tool": available[0], "reason": "Continuing automated audit."}
                yield stream_line("PLAN", f"Trying {_tool_label(available[0])} — AKILI using fallback plan")
            else:
                yield stream_line("THINK", "No more tools available — wrapping up discovery phase")
                break
        if decision.get("done"):
            yield stream_line("THINK", decision.get("reason", "Agent decided the assessment is complete"))
            yield stream_line("AI", "Discovery complete — preparing report")
            break
        tool = _normalize_tool(decision.get("tool") or "")
        if not tool or tool in context["tools_used"]:
            yield stream_line("THINK", "Skipping duplicate or unknown tool — finishing discovery")
            break
        if allowed_set and tool not in allowed_set:
            context["tools_used"].append(tool)
            yield stream_line("THINK", f"{tool} is not applicable to {module} scans — finishing")
            break
        reason = decision.get("reason", "Follow-up check recommended")
        priority = decision.get("priority", "medium")
        yield stream_line("PLAN", f"Trying {_tool_label(tool)} ({priority}) — {reason}")
        yield stream_line("PROGRESS", f"Now running {_tool_label(tool)}…")
        yield stream_line("TOOL", f"Executing {tool}…")
        context["scan_id"] = scan_id
        result = run_tool(tool, target, context)
        tool_count += 1
        if result:
            yield stream_line("OK", f"{_tool_label(tool)} complete")
            if str(result.get("severity", "")).lower() == "critical":
                yield stream_line("CRITICAL", f"{result.get('title')} — investigating further")
            else:
                yield stream_line("FOUND", result.get("summary", result.get("title", "")))
        else:
            yield stream_line("OK", f"{_tool_label(tool)} finished")

    yield stream_line("THINK", "AKILI synthesizing findings into your report…")
    yield stream_line("AI", "AKILI writing executive summary…")
    if module == "person":
        osint_data = context.get("osint") or {}
        ai = ask_groq(PERSON_PROMPT, json.dumps(osint_data, default=str)[:12000], scan_tier, expected_schema="person")
        if not isinstance(ai, dict):
            ai = {}
        if not ai:
            ai = {
                "name": target.split("|")[0],
                "confidence": 50,
                    "platforms": osint_data.get("platforms", {}),
                "trust_signals": ["Public search completed"],
                "red_flags": [],
                "ai_summary": "Limited analysis — check AKILI API configuration.",
                "overall_assessment": "verify further",
            }
        cb = osint_data.get("confidence_breakdown", {})
        report = {
            **ai,
            "scan_type": "person",
            "target": target,
            "score": ai.get("confidence", cb.get("score", 50)),
            "confidence": ai.get("confidence", cb.get("score", 50)),
            "verified_images": osint_data.get("verified_images", []),
            "web_images": osint_data.get("web_images", []),
            "images": osint_data.get("web_images", []),
                "social_cards": osint_data.get("social_cards", []),
                "breaches": osint_data.get("breaches", []),
                "platforms": osint_data.get("platforms", {}),
                "raw_results": osint_data.get("raw_results", []),
                "all_urls": osint_data.get("all_urls", []),
            "trust_signals": ai.get("trust_signals", cb.get("signals", [])),
            "red_flags": ai.get("red_flags", cb.get("red_flags", [])),
            "profile_narrative": ai.get("profile_narrative", ""),
            "age_context": ai.get("age_context", ""),
            "role_hint": ai.get("role_hint", ""),
            "location_hint": ai.get("location_hint", ""),
            "confidence_breakdown": cb,
            "search_source": osint_data.get("search_source", ""),
            "agentic_notes": osint_data.get("agentic_notes", []),
        }
    elif module == "email":
        raw = _email_intel_from_context(context)
        payload = {"email_intel": raw, "findings": context.get("findings", [])}
        ai = ask_groq(EMAIL_PROMPT, json.dumps(payload, default=str)[:12000], scan_tier, expected_schema="email")
        if not isinstance(ai, dict):
            ai = {}
        if not ai:
            ai = {}
        report = _merge_email_report(context, raw, ai)
    elif module == "ip":
        payload = {"ip_intel": context.get("ip_intel"), "tool_results": context.get("tool_results", [])}
        for tr in context.get("tool_results", []):
            if tr.get("tool") == "ip_intel":
                payload["ip_intel"] = tr.get("raw", {})
        ai = ask_groq(IP_PROMPT, json.dumps(payload, default=str)[:12000], scan_tier, expected_schema="ip")
        if not isinstance(ai, dict):
            ai = {}
        report = _merge_ip_report(context, ai if ai else {})
    elif module in ("website", "vulnerability", "subdomains", "organization", "company", "domain"):
        payload = _build_website_ai_payload(context)
        ai = ask_groq(FINAL_WEBSITE_PROMPT, json.dumps(payload, default=str)[:12000], scan_tier, expected_schema="website")
        if not isinstance(ai, dict):
            ai = {}
        report = _merge_website_report(context, ai if ai else _fallback_report(context))
    else:
        payload = _build_website_ai_payload(context)
        ai = ask_groq(FINAL_WEBSITE_PROMPT, json.dumps(payload, default=str)[:12000], scan_tier, expected_schema="website")
        if not isinstance(ai, dict):
            ai = {}
        report = _merge_website_report(context, ai if ai else _fallback_report(context))

    duration = int((time.time() - start) * 1000)
    report["scan_id"] = scan_id
    # Human-review gate: flag reports that are high-risk or very low-scoring
    try:
        needs_review = False
        score_raw = report.get("score")
        score = int(score_raw) if score_raw is not None else None
        grade = str(report.get("grade", "")).upper()
        legitimacy = report.get("legitimacy", "")
        findings = report.get("findings", []) or []
        crit_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
        if (score is not None and score < 40) or grade == "F" or legitimacy == "suspicious" or crit_count > 0:
            needs_review = True
        if needs_review:
            report["needs_manual_review"] = True
            try:
                log_audit(action="llm.flag_for_review", resource_type="scan", resource_id=scan_id, detail=f"score={score} grade={grade} legitimacy={legitimacy}", meta={"scan_id": scan_id, "score": score, "grade": grade, "legitimacy": legitimacy})
            except Exception:
                logger.debug("Failed to write review audit log")
    except Exception:
        logger.exception("Error evaluating review gate")

    save_scan(scan_id, module, target, report, tool_count, duration, user_id=user_id)
    yield stream_line("DONE", "Report ready")
    yield f"COMPLETE:{json.dumps(report)}\n"
