"""LLM providers: Groq primary, Gemini (free tier) fallback, rule-based last resort."""

import json
import logging
import os
import re

import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
import jsonschema
from dotenv import load_dotenv
from groq import Groq
from audit_log import log_audit
from database import save_llm_call

load_dotenv()
logger = logging.getLogger("akili.llm")

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
        logger.warning("Groq failed: %s", str(e)[:120])
        return None


def _ask_gemini(system: str, user: str) -> dict | None:
    if not GEMINI_API_KEY:
        return None
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    )
    prompt = f"{system}\n\n---\n\n{user[:12000]}\n\nRespond with valid JSON only."
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
            logger.warning("Gemini HTTP %s", r.status_code)
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
        logger.warning("Gemini failed: %s", str(e)[:120])
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


def _ask_cohere(system: str, user: str) -> dict | None:
    key = (os.getenv("COHERE_API_KEY", "") or "").strip()
    model = os.getenv("COHERE_MODEL", "command-xlarge-2023-08-22")
    if not key:
        return None
    prompt = f"{system}\n\n---\n\n{user[:12000]}\n\nRespond with valid JSON only."
    try:
        with httpx.Client(timeout=45) as client:
            r = client.post(
                "https://api.cohere.ai/generate",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": model, "prompt": prompt, "temperature": 0.0, "max_tokens": 1024},
            )
        if r.status_code != 200:
            logger.warning("Cohere HTTP %s", r.status_code)
            return None
        data = r.json()
        text = "\n".join([c.get("text", "") for c in data.get("generations", [])])
        out = parse_json_response(text)
        try:
            save_llm_call("cohere", model, prompt, text, out)
        except Exception:
            logger.debug("Failed to persist cohere call")
        return out if out else None
    except Exception as e:
        logger.warning("Cohere failed: %s", str(e)[:120])
        return None


def _ask_hf(system: str, user: str) -> dict | None:
    key = (os.getenv("HF_API_KEY", "") or "").strip()
    model = os.getenv("HF_MODEL", "gpt2")
    if not key:
        return None
    prompt = f"{system}\n\n---\n\n{user[:8000]}\n\nRespond with valid JSON only."
    try:
        with httpx.Client(timeout=45) as client:
            r = client.post(
                f"https://api-inference.huggingface.co/models/{model}",
                headers={"Authorization": f"Bearer {key}"},
                json={"inputs": prompt, "parameters": {"max_new_tokens": 1024, "temperature": 0.0}},
            )
        if r.status_code != 200:
            logger.warning("HuggingFace HTTP %s", r.status_code)
            return None
        data = r.json()
        # HF inference may return list of dicts or text
        text = ""
        if isinstance(data, list):
            for item in data:
                text += item.get("generated_text", "")
        else:
            text = data.get("generated_text", "") if isinstance(data, dict) else str(data)
        out = parse_json_response(text)
        try:
            save_llm_call("huggingface", model, prompt, text, out)
        except Exception:
            logger.debug("Failed to persist huggingface call")
        return out if out else None
    except Exception as e:
        logger.warning("HuggingFace failed: %s", str(e)[:120])
        return None


def _ask_openrouter(system: str, user: str) -> dict | None:
    key = (os.getenv("OPENROUTER_API_KEY", "") or "").strip()
    model = os.getenv("OPENROUTER_MODEL", "oai-models/gpt-4o-mini")
    if not key:
        return None
    prompt = f"{system}\n\n---\n\n{user[:12000]}\n\nRespond with valid JSON only."
    try:
        with httpx.Client(timeout=45) as client:
            r = client.post(
                "https://api.openrouter.ai/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.0, "max_tokens": 1024},
            )
        if r.status_code != 200:
            logger.warning("OpenRouter HTTP %s", r.status_code)
            return None
        data = r.json()
        text = ""
        for c in data.get("choices", []):
            text += c.get("message", {}).get("content", "")
        out = parse_json_response(text)
        try:
            save_llm_call("openrouter", model, prompt, text, out)
        except Exception:
            logger.debug("Failed to persist openrouter call")
        return out if out else None
    except Exception as e:
        logger.warning("OpenRouter failed: %s", str(e)[:120])
        return None


def _ask_mistra(system: str, user: str) -> dict | None:
    # Placeholder for Mistra API; call only if MISTRA_API_KEY present
    key = (os.getenv("MISTRA_API_KEY", "") or "").strip()
    if not key:
        return None
    # Implement provider-specific request here when API details are available
    return None


def _is_valid_output(d: object) -> bool:
    if not isinstance(d, dict):
        return False
    # basic signals of structured AI output
    keys = set(d.keys())
    return bool(keys.intersection({"score", "grade", "summary", "findings", "risk_level", "recommendations"}))


def _enhance_system_prompt(system: str) -> str:
    base = (system or "").strip()
    if len(base) >= 160:
        return base
    # Wrap short prompts with a richer, security-focused instruction set
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


# Minimal JSON Schemas for validation of common prompts
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
        "required": ["name", "confidence"],
        "properties": {"name": {"type": "string"}, "confidence": {"type": "number", "minimum": 0, "maximum": 100}},
    },
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


def _ask_all_providers(system: str, user: str, timeout: int = 45) -> list[tuple[str, dict]]:
    """Call all configured providers in parallel and return list of (provider, parsed_json) for valid responses."""
    providers = [
        ("groq", _ask_groq),
        ("gemini", _ask_gemini),
        ("cohere", _ask_cohere),
        ("openrouter", _ask_openrouter),
        ("huggingface", _ask_hf),
        ("mistra", _ask_mistra),
    ]
    results: list[tuple[str, dict]] = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(fn, system, user): name for name, fn in providers}
        for fut in as_completed(futures, timeout=timeout):
            name = futures[fut]
            try:
                out = fut.result()
            except Exception as e:
                logger.info("Provider %s failed: %s", name, str(e)[:120])
                continue
            if out and not out.get("error") and _is_valid_output(out):
                results.append((name, out))
    return results


def ask_llm(system: str, user: str, allow_ensemble: bool = False, expected_schema: str | None = None) -> tuple[dict, str]:
    """
    Try Groq → Gemini → rule-based by default. If `allow_ensemble` is True,
    call all configured providers in parallel and pick/merge the best valid response.
    Returns (parsed_json, provider_name).
    """
    # Strengthen short system prompts automatically to improve output quality
    system = _enhance_system_prompt(system)

    if allow_ensemble:
        candidates = _ask_all_providers(system, user)
        if candidates:
            # If expected_schema provided, prefer valid responses matching schema
            valid_candidates = []
            for name, out in candidates:
                is_valid, reason = (True, "no-schema") if not expected_schema else validate_schema(out, expected_schema)
                if is_valid:
                    valid_candidates.append((name, out, out.get("score") if isinstance(out.get("score"), (int, float)) else -1))
            if valid_candidates:
                # pick highest score among valid candidates
                valid_candidates.sort(key=lambda t: (t[2]), reverse=True)
                name, out, sc = valid_candidates[0]
                try:
                    log_audit(action="llm.call", resource_type="llm", detail=f"provider={name}", meta={"provider": name, "score": sc, "schema": expected_schema})
                except Exception:
                    logger.debug("Failed to write llm audit log")
                logger.info("Ensemble selected provider=%s (score=%s) matching schema=%s", name, sc, expected_schema)
                return out, name
            # otherwise fallback to best-scored candidate
            scored = []
            for name, out in candidates:
                score = out.get("score") if isinstance(out.get("score"), (int, float)) else -1
                scored.append((score, name, out))
            scored.sort(reverse=True, key=lambda t: (t[0], t[1]))
            best = scored[0]
            provider = best[1]
            try:
                log_audit(action="llm.call", resource_type="llm", detail=f"provider={provider}", meta={"provider": provider, "score": best[0]})
            except Exception:
                logger.debug("Failed to write llm audit log")
            logger.info("Ensemble selected provider=%s (score=%s)", provider, best[0])
            return best[2], provider
        # fall back to normal chain
    # Chain fallback: Groq then Gemini. Validate against expected_schema if provided.
    out = _ask_groq(system, user)
    if out and not out.get("error"):
        ok, reason = (True, "no-schema") if not expected_schema else validate_schema(out, expected_schema)
        try:
            log_audit(action="llm.call", resource_type="llm", detail="provider=groq", meta={"provider": "groq", "valid": ok, "schema": expected_schema, "reason": reason})
        except Exception:
            logger.debug("Failed to write llm audit log")
        if ok:
            return out, "groq"
        logger.info("Groq output failed schema: %s", reason)
    out = _ask_gemini(system, user)
    if out and not out.get("error"):
        ok, reason = (True, "no-schema") if not expected_schema else validate_schema(out, expected_schema)
        try:
            log_audit(action="llm.call", resource_type="llm", detail="provider=gemini", meta={"provider": "gemini", "valid": ok, "schema": expected_schema, "reason": reason})
        except Exception:
            logger.debug("Failed to write llm audit log")
        if ok:
            return out, "gemini"
        logger.info("Gemini output failed schema: %s", reason)
    # final fallback: rule-based deterministic heuristic
    return _rule_based(system, user), "rule-based"
