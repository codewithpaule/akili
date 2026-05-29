"""AI-driven person investigation — planning, profile verification, synthesis."""

from __future__ import annotations

import json
import re
from typing import Any

PERSON_PLAN_PROMPT = """You are AKILI's OSINT investigator. Plan a focused public investigation for one person.
Use the name and keywords to infer likely usernames and which platforms matter most.

Respond ONLY with valid JSON:
{
  "investigation_summary": "one sentence plan",
  "username_variants": ["variant1", "variant2"],
  "priority_platforms": ["linkedin", "github", "x", "instagram"],
  "profile_urls_to_check": [
    {"platform": "linkedin", "url": "https://linkedin.com/in/...", "reason": "why"}
  ],
  "verification_queries": ["optional short search phrases — max 3, only if needed"],
  "notes": ["assumptions or ambiguities"]
}

Rules:
- profile_urls_to_check: up to 8 plausible profile URLs (construct from name/username variants).
- Prefer linkedin.com/in, github.com, x.com, instagram.com profile URLs — not posts or search pages.
- verification_queries: use sparingly; empty array if direct profile checks are enough.
- Do not invent private data; only public profile URL patterns."""

PERSON_VERIFY_PROMPT = """You are AKILI verifying whether public profile pages belong to the subject.
Read the fetched page snippets and decide each candidate.

Subject name: {name}
Keywords: {keywords}

Respond ONLY with valid JSON:
{
  "verified_profiles": [
    {
      "platform": "linkedin|github|x|instagram",
      "url": "full https URL",
      "handle": "@user or slug",
      "confidence": "high|medium|low",
      "evidence": ["short reason from page text"],
      "display_name_on_profile": "",
      "bio_snippet": ""
    }
  ],
  "rejected": [
    {"url": "", "reason": "why rejected"}
  ],
  "person_overview": "2-4 sentence overview of who this person appears to be based ONLY on verified profiles",
  "identity_notes": "ambiguity warnings if any"
}

Rules:
- Only include profiles where page content clearly matches the subject name (and keywords when provided).
- Reject wrong-person results, fan pages, company pages, posts/reels, or generic search pages.
- high confidence requires name match in title/snippet AND role/location/keyword alignment when keywords exist.
- If no profile is verified, verified_profiles is [] and explain in person_overview."""

SOCIAL_HOSTS = frozenset({
    "linkedin.com", "www.linkedin.com",
    "github.com", "www.github.com",
    "x.com", "twitter.com", "www.twitter.com",
    "instagram.com", "www.instagram.com",
})


def _parse_json(text: str) -> dict:
    from agent import parse_json_response
    data = parse_json_response(text or "")
    return data if isinstance(data, dict) else {}


def _ask(system: str, user: str, schema: str) -> dict:
    from llm import ask_llm
    data, _provider = ask_llm(system, user, allow_ensemble=True, expected_schema=schema)
    return data if isinstance(data, dict) else {}


def username_variants(name: str, keywords: str = "") -> list[str]:
    parts = [p for p in re.findall(r"[a-zA-Z0-9]+", name) if len(p) > 1]
    if not parts:
        return []
    base = "".join(parts).lower()[:39]
    first, *rest = parts
    last = rest[-1] if rest else ""
    variants = {
        base,
        f"{first}{last}".lower(),
        f"{first}.{last}".lower(),
        f"{first}_{last}".lower(),
        f"{first}-{last}".lower(),
        first.lower(),
    }
    if keywords:
        for kw in re.findall(r"[a-zA-Z0-9]+", keywords)[:2]:
            if len(kw) > 2:
                variants.add(f"{first}{kw}".lower()[:39])
    return [v for v in variants if v and len(v) >= 2][:8]


def build_candidate_urls(name: str, keywords: str, plan: dict) -> list[dict]:
    """Merge AI-planned URLs with deterministic username guesses."""
    seen: set[str] = set()
    out: list[dict] = []

    def add(platform: str, url: str, reason: str = "") -> None:
        u = (url or "").strip()
        if not u or u in seen:
            return
        if not u.startswith("http"):
            u = f"https://{u.lstrip('/')}"
        seen.add(u)
        out.append({"platform": platform, "url": u, "reason": reason})

    for item in plan.get("profile_urls_to_check") or []:
        if isinstance(item, dict) and item.get("url"):
            add(str(item.get("platform", "profile")), item["url"], item.get("reason", "AI planned"))

    for variant in plan.get("username_variants") or username_variants(name, keywords):
        slug = re.sub(r"[^\w\-]", "", str(variant).lower())[:39]
        if not slug:
            continue
        add("linkedin", f"https://www.linkedin.com/in/{slug}", "username variant")
        add("github", f"https://github.com/{slug}", "username variant")
        add("x", f"https://x.com/{slug}", "username variant")
        add("instagram", f"https://www.instagram.com/{slug}", "username variant")

    return out[:16]


def plan_investigation(name: str, keywords: str) -> dict:
    payload = json.dumps({"name": name, "keywords": keywords}, ensure_ascii=False)
    plan = _ask(PERSON_PLAN_PROMPT, payload, "person_plan")
    if not plan:
        plan = {
            "investigation_summary": f"Check public profiles for {name}",
            "username_variants": username_variants(name, keywords),
            "priority_platforms": ["linkedin", "github", "x", "instagram"],
            "profile_urls_to_check": [],
            "verification_queries": [],
        }
    plan.setdefault("username_variants", username_variants(name, keywords))
    plan["candidates"] = build_candidate_urls(name, keywords, plan)
    return plan


def verify_profiles(name: str, keywords: str, candidates: list[dict]) -> dict:
    """AI verification from fetched profile snippets."""
    evidence = []
    for c in candidates[:12]:
        fp = c.get("fetched_profile") or {}
        evidence.append({
            "platform": c.get("platform"),
            "url": c.get("url") or c.get("profile_url"),
            "handle": c.get("handle"),
            "http_status": fp.get("status"),
            "title": fp.get("title"),
            "description": fp.get("description"),
            "text_snippet": (fp.get("text_snippet") or "")[:1200],
        })
    system = PERSON_VERIFY_PROMPT.format(name=name, keywords=keywords or "(none)")
    result = _ask(system, json.dumps({"candidates": evidence}, ensure_ascii=False), "person_verify")
    if not result:
        result = {"verified_profiles": [], "rejected": [], "person_overview": "", "identity_notes": ""}
    return result


def is_social_profile_url(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower()
        return host in SOCIAL_HOSTS or any(host.endswith(f".{h}") for h in SOCIAL_HOSTS if "." not in h)
    except Exception:
        return False
