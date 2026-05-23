"""LLM providers: Groq primary, Gemini (free tier) fallback, rule-based last resort."""

import json
import logging
import os
import re

import httpx
from dotenv import load_dotenv
from groq import Groq

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
            temperature=0.2,
            max_tokens=4096,
        )
        out = parse_json_response(r.choices[0].message.content or "")
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
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096},
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


def ask_llm(system: str, user: str) -> tuple[dict, str]:
    """
    Try Groq → Gemini → rule-based.
    Returns (parsed_json, provider_name).
    """
    out = _ask_groq(system, user)
    if out and not out.get("error"):
        return out, "groq"
    out = _ask_gemini(system, user)
    if out and not out.get("error"):
        return out, "gemini"
    return _rule_based(system, user), "rule-based"
