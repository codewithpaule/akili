import inspect
import json
import logging
import os
import httpx
import re
import time
import uuid
from typing import Any, Generator
from functools import lru_cache
from datetime import datetime, timedelta
from urllib.parse import urlparse

from dotenv import load_dotenv
from groq import Groq

from database import create_session, save_scan, append_scan_log
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
from tools.security_teams import run_red_team, run_blue_team

load_dotenv()
logger = logging.getLogger("akili.agent")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "18") or 18)
# Support an "unlimited" mode for MAX_AGENT_ACTIONS via env values like '*', 'unlimited', '0', or empty
_raw_max_actions = (os.getenv("MAX_AGENT_ACTIONS", "10") or "").strip()
if _raw_max_actions.lower() in ("", "*", "unlimited", "0", "none"):
    MAX_AGENT_ACTIONS = None
else:
    try:
        MAX_AGENT_ACTIONS = int(_raw_max_actions)
    except Exception:
        MAX_AGENT_ACTIONS = 6
AGENT_ALLOWED_HOSTS = [h.strip().lower() for h in os.getenv("AGENT_ALLOWED_HOSTS", "").split(",") if h.strip()]

from cache import cache_get, cache_set, cache_key
from scan_messages import get as scan_msg, PERSON_MESSAGES


PLANNING_PROMPT = """You are AKILI, an elite offensive security operator running authorized reconnaissance.
Think like someone mapping a target before exploitation: find the paths that actually get owned —
exposed .env, git repos, admin panels, DB ports, EOL software with known CVEs, hardcoded keys,
GraphQL introspection, Spring actuators, phpMyAdmin, backup.zip, and subdomain takeover surface.

Stay non-destructive. Do not exploit, write files, mutate data, brute force, bypass authentication,
or run payloads that could disrupt a target. Be brutal in coverage and evidence quality, not in impact.

Scan type: {module}
Target: {target}

Build an aggressive investigation plan. Do NOT waste tools on redundant checks.
Mandatory chains when applicable:
  tech_fingerprint OR fingerprint → cve_lookup (always if versions found)
  subdomains → link_crawler OR exposed_files on high-value hosts
  headers → vulnerability (always for web targets)
  ports → port_scanner if anything suspicious opens
  exposed_files → web_search for leaked creds if critical paths found

Use web_search for: active CVE exploits, breach dumps, Pastebin/leak mentions, Shodan-style context.

Available tools: {available_tools}

Reply in valid JSON only:
{{
  "plan": [
    {{"tool": "tool_name", "reason": "what attack surface this exposes", "priority": "high|medium|low"}},
    ...
  ],
  "investigation_goal": "the concrete compromise path you are trying to confirm or rule out"
}}

Maximum {max_tools} tools. Order by exploitability and blast radius."""

CONFIDENCE_REVISE_PROMPT = """You are AKILI mid-intrusion assessment. Evidence so far is in the JSON.
If confidence is below 90, you are NOT done — add more tools to confirm exploit paths.
Respond in valid JSON only:
{{
  "confidence": <0-100 integer>,
  "plan": [{{"tool": "tool_name", "reason": "what this confirms for attackers", "priority": "high|medium|low"}}],
  "investigation_goal": "updated compromise hypothesis"
}}
confidence = how sure you are the report captures real exploitable risk (not just missing headers).
Only tools not in already_used. If critical/high findings exist and confidence < 85, add cve_lookup or web_search.
Maximum 8 tools in plan."""

AGENT_SYSTEM_PROMPT = """You are AKILI, an offensive security agent on an authorized assessment.
Your job is to find what attackers would find: leaked secrets, known CVEs on detected versions,
internet-exposed admin/database panels, weak auth, and takeover paths.
Chain tools relentlessly. Never stop at headers alone. Use web_search for CVE exploitability and leak intel.
Respond with tool calls when you need more data. No exploit code, no credential attacks, no destructive checks. Recon and evidence only."""

def _target_param_schema(description: str = "URL, hostname, IP, email, or identifier"):
    return {
        "type": "object",
        "properties": {"target": {"type": "string", "description": description}},
        "required": ["target"],
    }

TOOL_DEFINITIONS = [
    {"type": "function", "function": {"name": "ssl_check", "description": "Check TLS certificate validity, chain, expiry, and cipher strength", "parameters": _target_param_schema("URL or hostname to scan")}},
    {"type": "function", "function": {"name": "headers", "description": "Analyze HTTP security headers, cookies, redirects, and page metadata", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "whois_check", "description": "WHOIS registration and DNS records for a domain", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "dns", "description": "DNS record lookup only (A, MX, TXT, NS)", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "ports", "description": "Probe common open ports and services", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "port_scanner", "description": "Extended port scan with service detection", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "fingerprint", "description": "Detect web technologies and frameworks", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "tech_fingerprint", "description": "Deep technology fingerprint with versions", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "cve_lookup", "description": "Look up CVEs for detected software versions", "parameters": {"type": "object", "properties": {"target": {"type": "string", "description": "Hostname context"}}, "required": []}}},
    {"type": "function", "function": {"name": "exposed_files", "description": "Probe for exposed config, backup, and sensitive files", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "vulnerability", "description": "Check for common web vulnerability patterns", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "subdomains", "description": "Discover subdomains via certificate transparency and DNS", "parameters": _target_param_schema("Domain or hostname")}},
    {"type": "function", "function": {"name": "ip_intel", "description": "Geolocation, ASN, reverse DNS, and hosted domains for an IP", "parameters": _target_param_schema("Public IP address")}},
    {"type": "function", "function": {"name": "org_scan", "description": "Organization footprint and ASN intelligence", "parameters": _target_param_schema("Organization name or domain")}},
    {"type": "function", "function": {"name": "email_intel", "description": "Email breach check, MX validation, disposable detection", "parameters": _target_param_schema("Email address")}},
    {"type": "function", "function": {"name": "domain_rep", "description": "Domain reputation and blacklist checks", "parameters": _target_param_schema("Domain name")}},
    {"type": "function", "function": {"name": "osint_person", "description": "Person OSINT across public profiles and web sources", "parameters": _target_param_schema("Person name or name|keywords")}},
    {"type": "function", "function": {"name": "link_crawler", "description": "Crawl links and discover hidden paths on a website", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "red_team", "description": "Offensive recon map attack surface, risky ports, exposed paths, EOL software without exploitation", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "blue_team", "description": "Defensive review missing security headers, hardening score, monitoring gaps", "parameters": _target_param_schema()}},
    {"type": "function", "function": {"name": "web_search", "description": "Search the web for current threat intelligence, CVE details, breach news, or public information about a target. Use when scan evidence is not enough.", "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "A focused search query"}, "intent": {"type": "string", "description": "What you are hoping to find"}}, "required": ["query"]}}},
]

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
    "red_team": lambda t, c: run_red_team(t, c),
    "blue_team": lambda t, c: run_blue_team(t, c),
    "web_search": lambda t, c: _web_search(c.get("_tool_query", t), c.get("_tool_intent", ""), c),
}

FINAL_WEBSITE_PROMPT = """You are AKILI writing a penetration-test style report for the site owner.
Use ONLY the evidence JSON. Be precise, brutal, and accurate — no fear-mongering, no invented CVEs.

Produce JSON:
{{
  "grade":"A-F",
  "score":0-100,
  "summary":"3 sentences: worst risks first, what an attacker would do next",
  "site_purpose":"what this site actually is",
  "legitimacy":"likely_legit|suspicious|unclear",
  "legitimacy_notes":"evidence only",
  "attack_surface_summary":"2 sentences on total exposure",
  "findings":[
    {{
      "severity":"critical|high|medium|low|info",
      "name":"short title",
      "explanation":"what was found and why attackers care",
      "recommendation":"exact fix",
      "cve_id":"CVE-YYYY-NNNN if evidence supports it, else empty string",
      "cvss":0.0,
      "attack_path":"one-line chain e.g. exposed .env → DB creds → data exfil",
      "exploitable":"confirmed|likely|unknown"
    }}
  ]
}}

Rules:
- Merge duplicate findings. Include ALL critical/high items from tool_findings and confirmed_exposed_paths.
- Use critical when: .env/git/credentials exposed, RCE CVEs on detected versions, public DB admin, open Redis/Mongo/MySQL, hardcoded cloud keys.
- Use high when: missing CSP/HSTS on auth sites, CSRF on login, phpMyAdmin public, directory listing, SQL errors, debug traces.
- Include cve_id ONLY when cve_matches or technologies+cve data support it.
- exploitable=confirmed only with direct evidence (exposed file content, matching CVE on exact version).
- Do not invent breach data or malware. No exploit code or payloads.
- .edu/.gov sites: likely_legit unless phishing/malware evidence. Missing headers alone ≠ F grade.
- Score: start 100, subtract critical×25, high×12, medium×5. Floor 35 for .edu unless critical exposure."""

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

PERSON_PROMPT = """You are a professional investigator writing a clear, honest profile
of a real person based entirely on publicly available information.

Write in natural, plain English. No bullet points. No em dashes. No corporate language.
Sound like a knowledgeable colleague describing someone to another colleague.

From the OSINT data provided, produce this exact JSON:
{{
  "name": "their full name as it appears in results",
  "confidence": 0-100,
  "person_overview": "3 to 5 sentences describing who this person is, what they do, where they appear to be based, and what they are publicly known for. If information is limited, be honest about that. Do not invent details.",
  "platforms": {{}},
  "personal_website": {{"url": "", "confidence": ""}},
  "trust_signals": ["plain English signal 1", "signal 2"],
  "red_flags": ["plain English flag 1"],
  "profile_narrative": "A single paragraph you would be comfortable sharing with a client. Describe what is publicly known about this person. Mention their profession, location if known, and any notable public activity. End with an honest note about confidence level.",
  "age_context": "estimated age range or generation if inferable from context, or empty string",
  "role_hint": "their apparent profession or role",
  "location_hint": "city or country if identifiable",
  "overall_assessment": "proceed|verify further|insufficient data"
}}

Rules:
- Never invent facts. Only state what the evidence supports.
- If the search found multiple people with the same name, say so clearly in person_overview.
- overall_assessment is "proceed" only if confidence is above 70 and at least one profile
  is high-confidence. Otherwise "verify further" or "insufficient data".
- Do not use the word "leverage", "utilize", "state-of-the-art", or "cutting-edge".
- Do not start any sentence with "It is worth noting that".
- Write as if a real person wrote this."""


def _web_search(query: str, intent: str, context: dict) -> dict:
    from tools.async_util import run_async
    from tools.fallbacks import serpapi_search

    query = (query or "").strip()
    if not query:
        return {
            "tool": "web_search",
            "severity": "INFO",
            "title": "Web search",
            "summary": "No search query provided",
            "findings": [],
            "raw": {"query": "", "results": []},
        }

    async def _run():
        return await serpapi_search(query, "google", num=8)

    results = run_async(_run()) or []
    return {
        "tool": "web_search",
        "severity": "INFO",
        "title": "Web search",
        "summary": f"Found {len(results)} result(s) for: {query[:100]}",
        "detail": intent or query,
        "raw": {"query": query, "intent": intent, "results": results[:10], "serpapi_configured": bool(os.getenv("SERPAPI_KEY", "").strip())},
        "findings": [],
    }


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
    canonical = data.get("name") or name
    summary_name = canonical or name
    overview = (data.get("person_overview") or "")[:120]
    verified_count = len(data.get("social_cards") or [])
    findings = []
    if verified_count == 0:
        findings.append({
            "severity": "INFO",
            "name": "No verified public profile match",
            "explanation": "AKILI searched public profile candidates but did not find enough page-content evidence to confidently match this person.",
            "recommendation": "Try adding keywords such as city, employer, school, username, or profession.",
        })
    return {
        "tool": "osint_person",
        "severity": "INFO",
        "title": "Person OSINT",
        "detail": overview or "AI profile investigation complete",
        "summary": f"Verified {verified_count} public profile match(es) for {summary_name}" + (f" - {plat_summary}" if plat_summary else ""),
        "raw": data,
        "findings": findings,
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


def ask_groq(
    system: str,
    user: str,
    scan_tier: str = "trial",
    expected_schema: str | None = None,
    *,
    max_tokens: int = 800,
) -> dict:
    """Groq → Gemini (free) → rule-based fallback."""
    from llm import ask_llm
    data, provider = ask_llm(system, user, expected_schema=expected_schema, max_tokens=max_tokens)
    if provider != "groq":
        logger.info("LLM provider=%s", provider)
    return data


def _groq_chat(messages: list, tools: list | None = None, tool_choice: str = "auto"):
    if not GROQ_API_KEY:
        return None
    client = _get_client()
    if not client:
        return None
    kwargs: dict[str, Any] = {
        "model": GROQ_MODEL,
        "messages": messages,
        "temperature": 0.0,
        "max_tokens": 800,
    }
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = tool_choice
    try:
        return client.chat.completions.create(**kwargs)
    except Exception as e:
        logger.warning("Groq tool chat failed: %s", str(e)[:200])
        return None


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
        "confirmed_exposed_paths": [],
        "open_ports": [],
        "tool_findings": context.get("findings", [])[:40],
        "cve_matches": [],
        "vulnerability_scan": [],
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
        if tool == "tech_fingerprint":
            detected = [
                {"name": t.get("name"), "version": t.get("version"), "confidence": t.get("confidence")}
                for t in (raw.get("technologies") or [])[:20]
            ]
            if detected:
                payload["technologies"] = detected
            payload["server"] = raw.get("server", "")
            payload["powered_by"] = raw.get("powered_by", "")
        if tool == "exposed_files":
            payload["confirmed_exposed_paths"] = raw.get("probes", [])[:30]
        if tool == "ports":
            payload["open_ports"] = raw.get("ports", [])[:15]
        if tool == "port_scanner":
            payload["port_scan"] = raw.get("ports", raw.get("open_ports", []))[:20]
        if tool == "cve_lookup":
            payload["cve_matches"] = raw.get("cves", raw.get("matches", []))[:25]
        if tool == "vulnerability":
            payload["vulnerability_scan"] = raw.get("vulnerabilities", [])[:25]
        if tool == "link_crawler":
            payload["hidden_paths"] = raw.get("hidden_paths", raw.get("interesting_links", []))[:20]
        if tool == "subdomains":
            payload["subdomains"] = (raw.get("active_subdomains") or raw.get("subdomains") or [])[:15]
    if host and (host.endswith(".edu.ng") or ".edu." in host or host.endswith(".edu")):
        payload["domain_profile"] = "academic"
    return payload


def _merge_ip_report(context: dict, ai: dict) -> dict:
    raw = context.get("ip_intel") or {}
    ports = list(raw.get("ports") or [])
    for tr in context.get("tool_results", []):
        if tr.get("tool") == "ip_intel":
            raw = tr.get("raw", raw)
            ports = list(raw.get("ports") or ports)
        elif tr.get("tool") == "ports":
            ports.extend((tr.get("raw", {}) or {}).get("ports", []) or [])
        elif tr.get("tool") == "port_scanner":
            ports.extend((tr.get("raw", {}) or {}).get("open_ports", []) or [])
    deduped_ports = []
    seen_ports = set()
    for p in ports:
        try:
            key = int(p.get("port"))
        except Exception:
            key = p.get("port")
        if key in seen_ports:
            continue
        seen_ports.add(key)
        deduped_ports.append(p)
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
        "ports": deduped_ports,
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
    "osint_person": "person OSINT (AI-led)",
    "web_search": "web threat intelligence search",
    "red_team": "red team attack surface",
    "blue_team": "blue team hardening review",
    "tech_fingerprint": "deep tech fingerprint",
    "cve_lookup": "CVE version lookup",
    "port_scanner": "extended port scan",
    "link_crawler": "link crawler",
    "dns": "DNS records",
}


def _tool_label(name: str) -> str:
    return TOOL_LABELS.get(name, name.replace("_", " "))


def _safe_tool_error(exc: Exception) -> str:
    raw = str(exc or "").strip()
    lowered = raw.lower()
    noisy_transport = (
        "tcptransport" in lowered
        or "handler is closed" in lowered
        or "transport closed" in lowered
        or "connection closed" in lowered
    )
    if noisy_transport:
        return "A network source closed during collection; the agent continued with the remaining evidence."
    if not raw:
        return "This check could not complete; the agent continued with the remaining evidence."
    return raw[:200]


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


def run_tool(name: str, target: str, context: dict, tool_args: dict | None = None) -> dict | None:
    name = str(name or "").strip().lower()
    if tool_args:
        context["_tool_query"] = tool_args.get("query", "")
        context["_tool_intent"] = tool_args.get("intent", "")
    module = context.get("module", "")
    
    # Check cache for expensive tools
    cacheable_tools = {
        "ssl_check": ("ssl", 1800),
        "whois_check": ("whois", 3600),
        "whois": ("whois", 3600),
        "fingerprint": ("fingerprint", 300),
        "headers": ("headers", 300),
        "ip_intel": ("ip_geo", 3600),
        "subdomains": ("subdomains", 1800),
    }
    if name in cacheable_tools:
        cache_name, ttl = cacheable_tools[name]
        key = cache_key(cache_name, target)
        cached = cache_get(key)
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
            cache_name, ttl = cacheable_tools[name]
            cache_set(cache_key(cache_name, target), result, ttl_seconds=ttl)
        
        context.setdefault("tool_results", []).append(result)
        for f in result.get("findings", []):
            context.setdefault("findings", []).append(f)
        _auto_chain_tools(name, result, context, allowed)
        return result
    except Exception as e:
        return {"tool": name, "severity": "info", "title": "Check incomplete", "summary": _safe_tool_error(e), "findings": []}


def _auto_chain_tools(name: str, result: dict, context: dict, allowed: set) -> None:
    """Queue follow-up tools when evidence demands deeper checks."""
    if not result:
        return
    queue = context.setdefault("_auto_chain_queue", [])
    used = set(context.get("tools_used", []))
    raw = result.get("raw", {}) or {}

    if name in ("fingerprint", "tech_fingerprint"):
        techs = raw.get("technologies") or raw.get("tech_stack") or []
        if techs:
            context["technologies"] = techs
            if "cve_lookup" not in used and ("cve_lookup" in allowed or not allowed):
                queue.append({"tool": "cve_lookup", "reason": "Map CVEs to detected software versions"})

    if name in ("headers", "fingerprint") and context.get("module") in ("website", "vulnerability", "api", "company"):
        if "vulnerability" not in used and "vulnerability" in allowed:
            queue.append({"tool": "vulnerability", "reason": "Deep vuln pass on fetched HTTP surface"})
        if "blue_team" not in used and "blue_team" in allowed:
            queue.append({"tool": "blue_team", "reason": "Defensive hardening review on HTTP surface"})

    if name in ("vulnerability", "exposed_files", "ports", "tech_fingerprint"):
        if "red_team" not in used and "red_team" in allowed:
            queue.append({"tool": "red_team", "reason": "Offensive attack surface synthesis"})

    if name == "exposed_files":
        critical = [p for p in (raw.get("probes") or []) if p.get("accessible") and str(p.get("severity", "")).upper() == "CRITICAL"]
        if critical and "web_search" not in used:
            host = context.get("target", "")
            queue.append({"tool": "web_search", "reason": "Check if exposed paths appear in public leak indexes", "query": f"{host} leaked credentials site:pastebin OR site:github"})

    if name == "ports":
        risky = {3306, 5432, 6379, 27017, 9200, 5984, 8080, 8443, 3389, 445, 23, 21}
        open_ports = {int(p.get("port", 0)) for p in (raw.get("ports") or []) if p.get("open")}
        if open_ports & risky and "port_scanner" not in used and "port_scanner" in allowed:
            queue.append({"tool": "port_scanner", "reason": "Extended scan on internet-exposed database/admin ports"})

    if name == "subdomains":
        active = raw.get("active_subdomains") or raw.get("subdomains") or []
        if len(active) >= 3 and "link_crawler" not in used and "link_crawler" in allowed:
            queue.append({"tool": "link_crawler", "reason": "Crawl active subdomains for hidden admin/API paths"})


def get_available_tools(module: str) -> list[str]:
    if module == "person":
        return ["osint_person", "web_search", "domain_rep", "email_intel"]
    base = [
        "headers", "ssl_check", "whois_check", "dns", "ports", "port_scanner",
        "fingerprint", "tech_fingerprint", "cve_lookup", "exposed_files",
        "link_crawler", "vulnerability", "subdomains", "web_search",
        "red_team", "blue_team",
    ]
    if module == "ip":
        return ["ip_intel", "ports", "port_scanner", "headers", "web_search"]
    if module == "email":
        return ["email_intel", "whois_check", "domain_rep", "web_search"]
    if module == "domain":
        return ["domain_rep", "whois_check", "dns", "subdomains", "web_search"]
    if module == "organization":
        return ["org_scan", "subdomains", "whois_check", "web_search"]
    if module == "company":
        return ["org_scan", "subdomains", "whois_check", "fingerprint", "web_search"]
    if module == "api":
        return ["headers", "fingerprint", "tech_fingerprint", "vulnerability", "exposed_files", "link_crawler", "cve_lookup", "web_search"]
    if module == "vulnerability":
        return [
            "vulnerability", "exposed_files", "headers", "ssl_check", "tech_fingerprint",
            "fingerprint", "cve_lookup", "ports", "port_scanner", "link_crawler", "subdomains", "web_search",
        ]
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
        if tool == "tech_fingerprint":
            techs = raw.get("technologies") or []
            if techs:
                report["tech_stack"] = [_normalize_tech_hint(t) for t in techs]
                report["cve_data_source"] = report.get("cve_data_source", "deep-fingerprint")
        if tool in ("whois_check", "whois", "dns"):
            if raw.get("dns"):
                report["dns"] = raw["dns"]
            if raw.get("whois"):
                report["whois"] = raw["whois"]
        if tool == "exposed_files":
            report["exposed_files"] = raw.get("probes", [])
        if tool == "subdomains":
            report["subdomains"] = raw.get("subdomains", [])
            report["active_subdomains"] = raw.get("active_subdomains", [])
            report["subdomain_count"] = len(raw.get("subdomains", []) or [])
            report["active_subdomain_count"] = raw.get("active_count", 0)
            report["hidden_links"] = raw.get("hidden_links", [])
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
    report["attack_surface_summary"] = ai.get("attack_surface_summary", "")
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


def _stream_tool_result(result: dict, tool: str, _emit, module: str = "website") -> Generator[str, None, None]:
    if not result:
        yield _emit("OK", scan_msg("clean", module))
        time.sleep(0)
        return
    sev = str(result.get("severity", "info")).upper()
    yield _emit("OK", f"{_tool_label(tool)} done")
    time.sleep(0)
    yield _emit("FOUND" if sev not in ("CRITICAL",) else "CRITICAL", result.get("summary", result.get("title", "")))
    time.sleep(0)
    for f in result.get("findings", []):
        fs = str(f.get("severity", "INFO")).upper()
        yield _emit("CRITICAL" if fs == "CRITICAL" else "FOUND", f.get("name", ""))
        time.sleep(0)
    try:
        raw = result.get("raw", {}) or {}
        if result.get("tool") in ("exposed_files", "exposed"):
            for a in raw.get("attempted", [])[:60]:
                path = a.get("path") or ""
                status = a.get("status") or 0
                acc = a.get("accessible")
                note = "exists" if acc else "not there"
                yield _emit("TOOL", f"{path} — HTTP {status} — {note}")
                time.sleep(0)
        if result.get("tool") in ("ports", "port_scanner", "port_scan") and module in ("website", "ip"):
            for p in (raw.get("ports") or raw.get("open_ports") or []):
                yield _emit("FOUND", f"Port {p.get('port')} open ({p.get('service')})")
                time.sleep(0)
        if result.get("tool") == "subdomains":
            for s in (raw.get("active_subdomains") or raw.get("subdomains") or [])[:40]:
                name = s.get("subdomain") or ""
                if name:
                    bits = [name]
                    if s.get("ip"):
                        bits.append(str(s.get("ip")))
                    if s.get("http_status"):
                        bits.append(f"HTTP {s.get('http_status')}")
                    yield _emit("FOUND", "Subdomain: " + " - ".join(bits))
                    time.sleep(0)
        if result.get("tool") in ("tech_fingerprint", "fingerprint") and module in ("website", "vulnerability", "company", "api"):
            techs = raw.get("technologies") or raw.get("tech_stack") or []
            for t in techs[:20]:
                nm = t.get("name") or ""
                ver = t.get("version") or ""
                if nm:
                    yield _emit("TOOL", f"Detected tech: {nm}" + (f" {ver}" if ver else ""))
                    time.sleep(0)
        if result.get("tool") == "web_search":
            for r in (raw.get("results") or [])[:5]:
                title = r.get("title") or r.get("link") or ""
                if title:
                    yield _emit("FOUND", title[:120])
                    time.sleep(0)
    except Exception:
        pass


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
        "scan_tier": scan_tier,
        "findings": [],
        "tools_used": [],
        "tool_results": [],
        "iteration": 0,
    }
    # scan_id available to all tools (e.g. fingerprint snapshots)
    tool_count = 0

    from scan_profile import profile_for_tier

    prof = profile_for_tier(scan_tier)
    if scan_tier == "guest":
        lite = True
    max_plan_tools = int(prof.get("max_plan_tools") or (4 if lite else 10))
    tier_max_iterations = int(prof.get("max_iterations") or MAX_ITERATIONS)

    def _emit(kind: str, msg: str) -> str:
        line = stream_line(kind, msg)
        try:
            append_scan_log(scan_id, kind, msg)
        except Exception:
            pass
        return line

    yield _emit("AKILI", scan_msg("start", module, target=target[:80]))
    time.sleep(0)
    yield _emit("THINK", f"Target: {target[:120]}")
    time.sleep(0)
    yield _emit("PLAN", scan_msg("planning", module))
    time.sleep(0)

    allowed_set = set(get_available_tools(module))
    available_tools_str = ", ".join(sorted(allowed_set))
    plan_data = ask_groq(
        "",
        PLANNING_PROMPT.format(
            module=module,
            target=target,
            available_tools=available_tools_str,
            max_tools=max_plan_tools,
        ),
        scan_tier,
        max_tokens=800,
    )
    if not isinstance(plan_data, dict):
        plan_data = {}

    plan_queue: list[dict] = []
    for item in (plan_data.get("plan") or [])[:max_plan_tools]:
        tname = str(item.get("tool") or "").strip().lower()
        if tname in allowed_set or tname == "web_search":
            plan_queue.append(item)

    if not plan_queue and allowed_set:
        defaults = {
            "email": "email_intel",
            "person": "osint_person",
            "vulnerability": "vulnerability",
            "ip": "ip_intel",
        }
        first = defaults.get(module) or "headers"
        plan_queue = [{"tool": first, "reason": "Initial attack-surface mapping", "priority": "high"}]
        if module in ("website", "vulnerability", "api"):
            for extra in ("exposed_files", "tech_fingerprint", "cve_lookup"):
                if extra in allowed_set and len(plan_queue) < max_plan_tools:
                    plan_queue.append({"tool": extra, "reason": f"Deep check: {extra}", "priority": "high"})

    context["plan"] = plan_queue
    context["investigation_goal"] = plan_data.get("investigation_goal", "")

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": AGENT_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"Scan type: {module}. Target: {target}. Goal: {context.get('investigation_goal', '')}",
        },
    ]

    confidence = 0
    low_confidence_extra = 0
    pending_tool_call_id: str | None = None

    def _should_stop() -> bool:
        cap = min(MAX_ITERATIONS, tier_max_iterations)
        if tool_count >= cap:
            return True
        crit = sum(1 for f in context.get("findings", []) if str(f.get("severity", "")).lower() == "critical")
        if confidence > 92 and tool_count >= 6:
            return True
        if confidence > 88 and tool_count >= 8 and crit == 0:
            return True
        if lite and tool_count >= tier_max_iterations:
            return True
        return False

    while not _should_stop():
        next_tool: str | None = None
        tool_args: dict[str, Any] = {}
        tool_target = target
        reason = ""
        pending_tool_call_id = None

        while plan_queue:
            item = plan_queue[0]
            tname = str(item.get("tool") or "").strip().lower()
            if tname in context.get("tools_used", []):
                plan_queue.pop(0)
                continue
            next_tool = tname
            reason = item.get("reason", "")
            plan_queue.pop(0)
            break

        if not next_tool:
            completion = _groq_chat(messages, tools=TOOL_DEFINITIONS, tool_choice="auto")
            if not completion:
                break
            msg = completion.choices[0].message
            if msg.tool_calls:
                tc = msg.tool_calls[0]
                next_tool = tc.function.name
                try:
                    tool_args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    tool_args = {}
                pending_tool_call_id = tc.id
                messages.append({
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                        }
                    ],
                })
                reason = "Agent requested follow-up check"
                tool_target = tool_args.get("target", target)
            else:
                if msg.content:
                    messages.append({"role": "assistant", "content": msg.content})
                break

        if not next_tool or next_tool in context.get("tools_used", []):
            break
        if allowed_set and next_tool not in allowed_set and next_tool != "web_search":
            context.setdefault("tools_used", []).append(next_tool)
            continue

        if reason:
            yield _emit("PLAN", scan_msg("tool_running", module, tool=_tool_label(next_tool)))
            time.sleep(0)
        yield _emit("TOOL", scan_msg("tool_running", module, tool=_tool_label(next_tool)))
        time.sleep(0)
        context["scan_id"] = scan_id

        exec_args = tool_args if next_tool == "web_search" else None
        exec_target = tool_target if next_tool != "web_search" else target
        result = run_tool(next_tool, exec_target, context, exec_args)
        tool_count += 1

        for line in _stream_tool_result(result, next_tool, _emit, module):
            yield line

        result_payload = json.dumps(result or {}, default=str)[:8000]
        if pending_tool_call_id:
            messages.append({
                "role": "tool",
                "tool_call_id": pending_tool_call_id,
                "content": result_payload,
            })
        else:
            messages.append({
                "role": "user",
                "content": f"Tool {next_tool} completed. Result JSON: {result_payload}",
            })

        revise_user = json.dumps({
            "already_used": context.get("tools_used", []),
            "findings_count": len(context.get("findings", [])),
            "investigation_goal": context.get("investigation_goal", ""),
            "module": module,
            "target": target,
        }, default=str)
        revision = ask_groq(CONFIDENCE_REVISE_PROMPT, revise_user, scan_tier, max_tokens=500)
        if isinstance(revision, dict):
            try:
                confidence = int(revision.get("confidence", confidence))
            except (TypeError, ValueError):
                pass
            if revision.get("investigation_goal"):
                context["investigation_goal"] = revision["investigation_goal"]
            revise_cap = 3 if lite else 8
            for item in (revision.get("plan") or [])[:revise_cap]:
                tname = str(item.get("tool") or "").strip().lower()
                if tname and tname not in context.get("tools_used", []) and (tname in allowed_set or tname == "web_search"):
                    if not any(p.get("tool") == tname for p in plan_queue):
                        plan_queue.append(item)

        for item in context.pop("_auto_chain_queue", []) or []:
            tname = str(item.get("tool") or "").strip().lower()
            if tname and tname not in context.get("tools_used", []) and (not allowed_set or tname in allowed_set or tname == "web_search"):
                if not any(p.get("tool") == tname for p in plan_queue):
                    plan_queue.append(item)
                    chain_reason = (item.get("reason") or "")[:100]
                    yield _emit("PLAN", f"Auto-chain → {_tool_label(tname)}" + (f": {chain_reason}" if chain_reason else ""))
                    time.sleep(0)

        yield _emit("THINK", scan_msg("thinking", module))
        time.sleep(0)

        if confidence < 40 and tool_count >= 6:
            low_confidence_extra += 1
            if low_confidence_extra > 3:
                yield _emit("THINK", scan_msg("wrapping_up", module))
                time.sleep(0)
                break

    yield _emit("THINK", scan_msg("wrapping_up", module))
    time.sleep(0)
    yield _emit("AI", scan_msg("report", module))
    time.sleep(0)
    if module == "person":
        osint_data = context.get("osint") or {}
        ai = ask_groq(
            PERSON_PROMPT,
            json.dumps(osint_data, default=str)[:12000],
            scan_tier,
            expected_schema="person",
            max_tokens=2000,
        )
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
            "name": ai.get("name") or osint_data.get("name") or target.split("|")[0],
            "score": ai.get("confidence", cb.get("score", 50)),
            "confidence": ai.get("confidence", cb.get("score", 50)),
            "best_match_confidence": osint_data.get("best_match_confidence", "none"),
            "personal_website": osint_data.get("personal_website") or ai.get("personal_website"),
            "news_mentions": osint_data.get("news_mentions", []),
            "profile_images": osint_data.get("profile_images", []),
            "all_images": osint_data.get("all_images", []),
            "web_images": osint_data.get("web_images", []),
            "images": osint_data.get("all_images") or osint_data.get("web_images", []),
            "social_cards": osint_data.get("social_cards", []),
            "breaches": osint_data.get("breach_data", {}).get("breaches", []) if isinstance(osint_data.get("breach_data"), dict) else [],
            "platforms": osint_data.get("platforms", {}),
            "raw_results": osint_data.get("raw_results", []),
            "all_urls": osint_data.get("all_urls", []),
            "trust_signals": ai.get("trust_signals", cb.get("signals", [])),
            "red_flags": ai.get("red_flags", cb.get("red_flags", [])),
            "profile_narrative": ai.get("profile_narrative", ""),
            "ai_summary": ai.get("profile_narrative") or ai.get("person_overview") or osint_data.get("person_overview", ""),
            "age_context": ai.get("age_context", ""),
            "role_hint": ai.get("role_hint", ""),
            "location_hint": ai.get("location_hint", ""),
            "confidence_breakdown": cb,
            "search_source": osint_data.get("search_source", ""),
            "agentic_notes": osint_data.get("agentic_notes", []),
            "person_overview": ai.get("person_overview") or osint_data.get("person_overview", ""),
            "identity_notes": osint_data.get("identity_notes", ""),
            "investigation_plan": osint_data.get("investigation_plan", ""),
            "findings": context.get("findings", []),
        }
    elif module == "email":
        raw = _email_intel_from_context(context)
        payload = {"email_intel": raw, "findings": context.get("findings", [])}
        ai = ask_groq(EMAIL_PROMPT, json.dumps(payload, default=str)[:12000], scan_tier, expected_schema="email", max_tokens=800)
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
        ai = ask_groq(IP_PROMPT, json.dumps(payload, default=str)[:12000], scan_tier, expected_schema="ip", max_tokens=800)
        if not isinstance(ai, dict):
            ai = {}
        report = _merge_ip_report(context, ai if ai else {})
    elif module in ("website", "vulnerability", "subdomains", "organization", "company", "domain"):
        payload = _build_website_ai_payload(context)
        ai = ask_groq(FINAL_WEBSITE_PROMPT, json.dumps(payload, default=str)[:12000], scan_tier, expected_schema="website", max_tokens=3000)
        if not isinstance(ai, dict):
            ai = {}
        report = _merge_website_report(context, ai if ai else _fallback_report(context))
    else:
        payload = _build_website_ai_payload(context)
        ai = ask_groq(FINAL_WEBSITE_PROMPT, json.dumps(payload, default=str)[:12000], scan_tier, expected_schema="website", max_tokens=3000)
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
    yield _emit("DONE", "Your report is ready")
    time.sleep(0)
    yield f"COMPLETE:{json.dumps(report)}\n"
