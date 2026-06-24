"""LLM providers: Groq primary, Gemini (free tier) fallback, rule-based last resort."""

import json
import logging
import os
import re
import time

import httpx
import jsonschema
from dotenv import load_dotenv
from groq import Groq
from audit_log import log_audit
from database import save_llm_call

load_dotenv()
logger = logging.getLogger("akili.llm")

API_SCAN_PROMPT = (
    "You are an expert API analyst. Given the HTTP request and response details, produce a concise JSON summary. "
    "Return valid JSON only with the following top-level fields when applicable: `summary` (short description), "
    "`endpoints` (array of observed endpoint patterns), `methods` (array of supported HTTP methods), `status_codes` "
    "(list of common response codes), `content_types` (list of observed Content-Types), `security_issues` (array of strings), "
    "and `recommendations` (array of actionable suggestions). Be factual and base conclusions on headers and response bodies provided."
)

GROQ_API_KEY = (os.getenv("GROQ_API_KEY", "") or "").strip()
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY", "") or "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")


def parse_json_response(text: str) -> dict:
    text = (text or "").strip()
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if m:
        text = m.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m2 = re.search(r"\{[\s\S]*\}", text)
        return json.loads(m2.group()) if m2 else {}


def _ask_groq(system: str, user: str) -> dict | None:
    if not GROQ_API_KEY:
        return None
    attempts = 3
    backoff = 1.0
    for attempt in range(1, attempts + 1):
        try:
            client = Groq(api_key=GROQ_API_KEY)
            r = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user[:14000]},
                ],
                temperature=0.0,
                max_tokens=4096,
            )
            raw_text = r.choices[0].message.content or ""
            out = parse_json_response(raw_text)
            try:
                save_llm_call("groq", GROQ_MODEL, system + "\n\n---\n\n" + user[:14000], raw_text, out)
            except Exception:
                logger.debug("Failed to persist groq call")
            return out if out else None
        except Exception as e:
            msg = str(e)
            logger.warning("Groq attempt %s failed: %s", attempt, msg[:200])
            if attempt < attempts and ("rate limit" in msg.lower() or "429" in msg or "timed out" in msg.lower() or "connection" in msg.lower()):
                time.sleep(backoff)
                backoff *= 2
                continue
            return None


def _ask_gemini(system: str, user: str) -> dict | None:
    if not GEMINI_API_KEY:
        return None
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    )
    prompt = f"{system}\n\n---\n\n{user[:12000]}\n\nRespond with valid JSON only."
    attempts = 3
    backoff = 1.0
    for attempt in range(1, attempts + 1):
        try:
            with httpx.Client(timeout=45) as client:
                r = client.post(
                    url,
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {"temperature": 0.0, "maxOutputTokens": 4096},
                    },
                )
            if r.status_code != 200:
                logger.warning("Gemini HTTP %s (attempt %s)", r.status_code, attempt)
                if attempt < attempts and r.status_code in (429, 502, 503, 504):
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                return None
            data = r.json()
            text = ""
            for cand in data.get("candidates", []):
                for part in cand.get("content", {}).get("parts", []):
                    text += part.get("text", "")
            out = parse_json_response(text)
            try:
                save_llm_call("gemini", GEMINI_MODEL, prompt, text, out)
            except Exception:
                logger.debug("Failed to persist gemini call")
            return out if out else None
        except Exception as e:
            msg = str(e)
            logger.warning("Gemini attempt %s failed: %s", attempt, msg[:200])
            if attempt < attempts and ("timed out" in msg.lower() or "connection" in msg.lower() or "name or service not known" in msg.lower()):
                time.sleep(backoff)
                backoff *= 2
                continue
            return None


def _rule_based(system: str, user: str) -> dict:
    """Minimal structured output when all cloud LLMs are unavailable."""
    try:
        ctx = json.loads(user) if user.strip().startswith("{") else {}
    except json.JSONDecodeError:
        ctx = {}
    breaches = ctx.get("breaches") or ctx.get("email_intel", {}).get("breaches") or []
    if not breaches and isinstance(ctx.get("tool_results"), list):
        for tr in ctx["tool_results"]:
            raw = tr.get("raw", {})
            if raw.get("breaches"):
                breaches = raw["breaches"]
                break
    if "breach" in system.lower() or "email" in user.lower()[:500]:
        n = len(breaches)
        return {
            "summary": (
                f"This email appears in {n} known breach(es). Change passwords and enable MFA."
                if n
                else "No breaches found in AKILI's free breach databases (XposedOrNot)."
            ),
            "risk_level": "high" if n else "low",
            "recommendations": [
                "Use unique passwords per site",
                "Enable two-factor authentication",
                "Check haveibeenpwned.com for full history",
            ],
        }
    findings = ctx.get("findings", [])
    score = max(25, 88 - len(findings) * 4)
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D"
    return {
        "grade": grade,
        "score": score,
        "summary": "Automated scan completed (AKILI rule-based summary — configure Groq or Gemini for richer analysis).",
        "findings": findings[:12],
        "site_purpose": ctx.get("page_description") or ctx.get("page_title") or "",
        "legitimacy": "unclear",
        "legitimacy_notes": "Enable GROQ_API_KEY or free GEMINI_API_KEY from Google AI Studio.",
    }


def _enhance_system_prompt(system: str) -> str:
    base = (system or "").strip()
    if len(base) >= 160:
        return base
    wrapper = (
        "You are an expert security auditor and threat analyst. Provide concise, factual, and actionable findings. "
        "Always respond with valid JSON only (no extra commentary). Use the following top-level fields when applicable: "
        "`grade` (A-F), `score` (0-100), `summary`, `findings` (array of {title,severity,description,evidence}), `risk_level` (low|medium|high), "
        "`recommendations` (array of strings), and `next_actions` (suggested follow-up steps). Prioritize accuracy and include brief evidence for each finding. "
        "If asked to provide remediation steps, include prioritized, short instructions and recommended references. Obey context and do not assume access beyond provided data.\n\n"
    )
    if base:
        return wrapper + "Context: " + base
    return wrapper + "Context: Perform a thorough security assessment based on available tool outputs."


SCHEMAS = {
    "website": {
        "type": "object",
        "required": ["grade", "score", "summary"],
        "properties": {
            "grade": {"type": "string"},
            "score": {"type": "number", "minimum": 0, "maximum": 100},
            "summary": {"type": "string"},
            "findings": {"type": "array"},
        },
    },
    "person": {
        "type": "object",
        "required": ["name", "confidence", "overall_assessment"],
        "properties": {
            "name": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 100},
            "person_overview": {"type": "string"},
            "platforms": {"type": "object"},
            "trust_signals": {"type": "array"},
            "red_flags": {"type": "array"},
            "profile_narrative": {"type": "string"},
            "age_context": {"type": "string"},
            "role_hint": {"type": "string"},
            "location_hint": {"type": "string"},
            "ai_summary": {"type": "string"},
            "overall_assessment": {"type": "string", "enum": ["proceed", "verify further", "insufficient data"]},
        },
    },
    "person_plan": {"type": "object"},
    "person_verify": {"type": "object"},
    "email": {
        "type": "object",
        "required": ["summary", "risk_level"],
        "properties": {"summary": {"type": "string"}, "risk_level": {"type": "string"}},
    },
    "ip": {
        "type": "object",
        "required": ["summary", "risk_level"],
        "properties": {"summary": {"type": "string"}, "risk_level": {"type": "string"}},
    },
    "next_action": {
        "oneOf": [
            {"type": "object", "required": ["tool", "reason"], "properties": {"tool": {"type": "string"}, "reason": {"type": "string"}}},
            {"type": "object", "required": ["done"], "properties": {"done": {"type": "boolean"}}},
        ]
    },
}


def validate_schema(obj: dict, schema_name: str) -> tuple[bool, str]:
    schema = SCHEMAS.get(schema_name)
    if not schema:
        return True, "no-schema"
    try:
        jsonschema.validate(instance=obj, schema=schema)
        return True, "ok"
    except jsonschema.ValidationError as e:
        return False, str(e.message)


def ask_llm(system: str, user: str, expected_schema: str | None = None) -> tuple[dict, str]:
    """Try Groq, then Gemini, then rule-based fallback. Returns (parsed_json, provider_name)."""
    system = _enhance_system_prompt(system)

    configured_providers = bool(GROQ_API_KEY) or bool(GEMINI_API_KEY)

    chain_providers = [
        ("groq", _ask_groq),
        ("gemini", _ask_gemini),
    ]
    tried_any = False
    for name, fn in chain_providers:
        key_present = name == "groq" and GROQ_API_KEY or name == "gemini" and GEMINI_API_KEY
        if key_present:
            tried_any = True
        try:
            out = fn(system, user)
        except Exception as e:
            logger.info("Provider %s failed during chain: %s", name, str(e)[:120])
            out = None
        if not out:
            continue
        if out.get("error"):
            continue
        ok, reason = (True, "no-schema") if not expected_schema else validate_schema(out, expected_schema)
        try:
            log_audit(action="llm.call", resource_type="llm", detail=f"provider={name}", meta={"provider": name, "valid": ok, "schema": expected_schema, "reason": reason})
        except Exception:
            logger.debug("Failed to write llm audit log")
        if ok:
            return out, name
        logger.info("%s output failed schema: %s", name.capitalize(), reason)

    if tried_any:
        return ({"error": "akili_timed_out", "message": "AKILI timed out while contacting AI providers. Please try again later."}, "akili-timeout")

    return _rule_based(system, user), "rule-based"
