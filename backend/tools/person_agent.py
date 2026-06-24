"""AI-driven person investigation — planning, profile verification, synthesis."""

from __future__ import annotations

import json
import re
from typing import Any

PERSON_PLAN_PROMPT = """You are AKILI's OSINT investigator. Plan a thorough public investigation
for one person. Your job is to find out who this person is, what they do, and where they have
a public presence online — regardless of whether they are a developer, a doctor, a musician,
a politician, a business owner, a student, or anyone else.

Name: {name}
Keywords: {keywords}

Think about what the keywords suggest about this person's profession, industry, and likely
online behaviour. A musician will have Spotify, SoundCloud, YouTube. A doctor might have
HealthGrades or a hospital staff page. An academic will have Google Scholar or ResearchGate.
An entrepreneur will have Crunchbase or AngelList. A designer will have Behance or Dribbble.
A writer will have Medium, Substack, or Goodreads. A public figure might have Wikipedia.

Respond ONLY with valid JSON:
{{
  "investigation_summary": "one sentence plan",
  "person_type": "developer|creative|academic|business|public_figure|medical|general",
  "username_variants": ["variant1", "variant2"],
  "priority_platforms": ["list", "in", "priority", "order", "for", "this", "person"],
  "profile_urls_to_check": [
    {{"platform": "platform_name", "url": "https://...", "reason": "why likely"}}
  ],
  "web_search_queries": [
    "focused search query 1",
    "focused search query 2",
    "site:linkedin.com/in name keywords",
    "name keywords personal website OR portfolio"
  ],
  "image_search_queries": [
    "name keywords photo portrait",
    "name keywords headshot"
  ],
  "notes": ["assumptions or disambiguation hints"]
}}

Rules:
- profile_urls_to_check: up to 12 plausible profile URLs. Construct them from name and username
  variants. Cover multiple platform types suited to this person's likely profession.
- web_search_queries: 4 to 6 queries. One should target LinkedIn. One should target personal
  websites or portfolios. One should be a broad name-and-keyword search. One should search
  news or mentions.
- image_search_queries: 2 queries specifically for finding this person's photo.
- Do not limit yourself to developer platforms. Think about the whole internet.
- Do not invent private data. Only construct public-pattern URLs."""

PERSON_VERIFY_PROMPT = """You are AKILI verifying whether public pages belong to a specific person.
Read all the evidence carefully and make a confident decision for each candidate.

Subject name: {name}
Keywords / context: {keywords}

You will receive:
- Social media profile candidates (LinkedIn, Instagram, YouTube, etc.)
- Web search results that may include news articles, company staff pages,
  personal websites, academic pages, or other public mentions
- Page content snippets where available

For each profile or page that belongs to this person, extract everything useful:
- Their profile picture URL if visible in the page source
- Their bio or about text
- Their job title or role
- Their location
- Any linked websites or social accounts mentioned on the page

For web search results, identify:
- Their personal website or portfolio URL if one appears in results
- News articles or notable mentions

Respond ONLY with valid JSON:
{{
  "verified_profiles": [
    {{
      "platform": "platform name",
      "url": "full https URL",
      "handle": "@handle or slug",
      "confidence": "high|medium|low",
      "evidence": ["specific text from the page that confirms this is the right person"],
      "display_name_on_profile": "name shown on the profile",
      "bio_snippet": "their bio or about text from the page",
      "profile_image_url": "direct image URL if found in page source",
      "job_title": "their title or role if found",
      "location": "city or country if mentioned",
      "follower_count": "number as string if visible",
      "linked_website": "any personal site they link to from this profile"
    }}
  ],
  "personal_website": {{
    "url": "https://theirsite.com",
    "confidence": "high|medium|low",
    "evidence": "how you found it"
  }},
  "news_mentions": [
    {{"title": "article title", "url": "link", "summary": "one sentence"}}
  ],
  "rejected": [{{"url": "", "reason": "why this is the wrong person"}}],
  "person_overview": "3 to 5 sentence overview of who this person is, what they do, where they are based, and what they are known for. Write as if describing a real person to a colleague. Be specific. If you only have partial information, say so clearly.",
  "best_match_confidence": "high|medium|low|none",
  "identity_notes": "any ambiguity, multiple people with this name, or caveats"
}}

Rules:
- Only mark confidence as high if the page content explicitly names the person AND the
  keywords or context align.
- Medium confidence means the name matches but context alignment is uncertain.
- Low confidence means only a name match, no context verification.
- personal_website: set to null if no personal website found. This is any site they own
  that is not a social media platform (e.g. johnsmith.com, johnsmithdesign.co.uk).
- person_overview must be written in plain natural English. No bullet points. No dashes.
  No em dashes. If nothing was found, say: "We could not find enough public information
  to build a profile for this person. Try adding more context like their city, employer,
  or profession."
- Extract profile_image_url from og:image or avatar img src if present in the snippet."""

PLATFORM_URL_TEMPLATES = {
    "linkedin": "https://www.linkedin.com/in/{slug}",
    "github": "https://github.com/{slug}",
    "x": "https://x.com/{slug}",
    "instagram": "https://www.instagram.com/{slug}",
    "facebook": "https://www.facebook.com/{slug}",
    "tiktok": "https://www.tiktok.com/@{slug}",
    "youtube": "https://www.youtube.com/@{slug}",
    "reddit": "https://www.reddit.com/user/{slug}",
    "medium": "https://medium.com/@{slug}",
    "quora": "https://www.quora.com/profile/{slug}",
    "pinterest": "https://www.pinterest.com/{slug}",
    "behance": "https://www.behance.net/{slug}",
    "dribbble": "https://www.dribbble.com/{slug}",
    "soundcloud": "https://soundcloud.com/{slug}",
}


def _parse_json(text: str) -> dict:
    from agent import parse_json_response
    data = parse_json_response(text or "")
    return data if isinstance(data, dict) else {}


def _ask(system: str, user: str, schema: str, *, max_tokens: int = 1200) -> dict:
    from llm import ask_llm
    data, _provider = ask_llm(system, user, expected_schema=schema, max_tokens=max_tokens)
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

    priority = plan.get("priority_platforms") or ["linkedin", "x", "instagram", "youtube"]
    for variant in plan.get("username_variants") or username_variants(name, keywords):
        slug = re.sub(r"[^\w\-\.]", "", str(variant).lower())[:39]
        if not slug:
            continue
        for platform in priority[:8]:
            tpl = PLATFORM_URL_TEMPLATES.get(str(platform).lower())
            if tpl:
                add(platform, tpl.format(slug=slug), "username variant")

    return out[:12]


def plan_investigation(name: str, keywords: str) -> dict:
    system = PERSON_PLAN_PROMPT.format(name=name, keywords=keywords or "(none)")
    payload = json.dumps({"name": name, "keywords": keywords}, ensure_ascii=False)
    plan = _ask(system, payload, "person_plan", max_tokens=1200)
    if not plan:
        plan = {
            "investigation_summary": f"Check public profiles and web mentions for {name}",
            "person_type": "general",
            "username_variants": username_variants(name, keywords),
            "priority_platforms": ["linkedin", "x", "instagram", "youtube", "facebook"],
            "profile_urls_to_check": [],
            "web_search_queries": [
                f'"{name}" {keywords}'.strip(),
                f'site:linkedin.com/in "{name}" {keywords}'.strip(),
                f'"{name}" {keywords} news'.strip(),
            ],
            "image_search_queries": [
                f"{name} {keywords} photo portrait".strip(),
                f"{name} {keywords} headshot".strip(),
            ],
        }
    plan.setdefault("username_variants", username_variants(name, keywords))
    plan.setdefault("web_search_queries", [f'"{name}" {keywords}'.strip()])
    plan.setdefault("image_search_queries", [f"{name} {keywords} photo".strip()])
    plan["candidates"] = build_candidate_urls(name, keywords, plan)
    return plan


def verify_profiles(
    name: str,
    keywords: str,
    candidates: list[dict],
    *,
    web_results: list[dict] | None = None,
) -> dict:
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
            "og_image": fp.get("og_image"),
        })
    payload = {
        "profile_candidates": evidence,
        "web_search_results": (web_results or [])[:25],
    }
    system = PERSON_VERIFY_PROMPT.format(name=name, keywords=keywords or "(none)")
    result = _ask(system, json.dumps(payload, ensure_ascii=False), "person_verify", max_tokens=2000)
    if not result:
        result = {
            "verified_profiles": [],
            "rejected": [],
            "person_overview": "",
            "identity_notes": "",
            "best_match_confidence": "none",
            "news_mentions": [],
            "personal_website": None,
        }
    pw = result.get("personal_website")
    if isinstance(pw, dict) and not pw.get("url"):
        result["personal_website"] = None
    return result


def is_social_profile_url(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower()
        social = (
            "linkedin.com", "github.com", "x.com", "twitter.com", "instagram.com",
            "facebook.com", "tiktok.com", "youtube.com", "reddit.com", "medium.com",
            "behance.net", "dribbble.com", "soundcloud.com", "spotify.com",
        )
        return any(host == h or host.endswith(f".{h}") for h in social)
    except Exception:
        return False
