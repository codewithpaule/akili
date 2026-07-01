"""Person OSINT collection — parallel profile fetch, search, and verification."""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any

from tools import person_agent
from tools.fallbacks import search_with_fallback, serpapi_image_search

PLATFORM_PATTERNS = {
    "linkedin": r"linkedin\.com/in/[\w\-]+",
    "github": r"github\.com/[\w\-]+(?:/[\w\-]+)?",
    "x": r"(?:twitter|x)\.com/[\w]+",
    "instagram": r"instagram\.com/[\w\.]+",
    "facebook": r"facebook\.com/(?:[\w\.]+|people/[\w\-]+/[\d]+)",
    "tiktok": r"tiktok\.com/@[\w\.]+",
    "youtube": r"youtube\.com/(?:@[\w\-]+|channel/[\w\-]+|c/[\w\-]+)",
    "reddit": r"reddit\.com/u(?:ser)?/[\w\-]+",
    "medium": r"medium\.com/@[\w\-]+",
    "substack": r"[\w\-]+\.substack\.com",
    "quora": r"quora\.com/profile/[\w\-]+",
    "pinterest": r"pinterest\.com/[\w_]+",
    "behance": r"behance\.net/[\w]+",
    "dribbble": r"dribbble\.com/[\w]+",
    "researchgate": r"researchgate\.net/profile/[\w\-]+",
    "academia": r"(?:[\w]+\.)?academia\.edu/[\w]+",
    "soundcloud": r"soundcloud\.com/[\w\-]+",
    "spotify": r"open\.spotify\.com/(?:artist|user|show|playlist)/[\w]+",
    "imdb": r"imdb\.com/name/nm[\d]+",
    "crunchbase": r"crunchbase\.com/person/[\w\-]+",
    "wikipedia": r"(?:en\.)?wikipedia\.org/wiki/[\w\(\)]+",
    "website": r"",
}

STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "official", "profile",
    "linkedin", "instagram", "twitter", "com", "www", "http", "https", "news",
    "latest", "photos", "images", "video", "videos", "about", "home",
}


def _empty_platforms() -> dict:
    return {p: {"found": False, "url": None} for p in PLATFORM_PATTERNS}


def _confidence_breakdown(
    platforms: dict,
    social_cards: list,
    personal_website: dict | None,
) -> dict:
    score = 20
    signals = []
    red_flags = []

    found_platforms = [p for p, info in platforms.items() if info.get("found")]
    high_confidence = [c for c in social_cards if c.get("confidence") == "high"]
    medium_confidence = [c for c in social_cards if c.get("confidence") == "medium"]

    for card in high_confidence:
        score += 20
        signals.append(f"Verified {card['platform']} profile with a strong public-content match")

    for card in medium_confidence:
        score += 10
        signals.append(f"Likely {card['platform']} profile found")

    if len(found_platforms) >= 3:
        score += 10
        signals.append(f"Presence across {len(found_platforms)} platforms looks consistent")

    if personal_website and personal_website.get("url"):
        score += 15
        signals.append("Personal website found")

    if not social_cards:
        red_flags.append("No profiles could be verified from the available search results.")
        red_flags.append("Try adding more context like a city, employer, school, or username.")

    return {
        "score": max(0, min(100, score)),
        "signals": signals,
        "red_flags": red_flags,
        "breakdown_visible": False,
    }


def _abs_url(url: str | None) -> str | None:
    if not url:
        return None
    u = str(url).strip()
    if not u:
        return None
    if re.match(r"^https?://", u, re.I):
        return u
    if u.startswith("//"):
        return f"https:{u}"
    return f"https://{u.lstrip('/')}"


def _platform_from_url(url: str) -> str | None:
    for platform, pattern in PLATFORM_PATTERNS.items():
        if platform == "website" or not pattern:
            continue
        if re.search(pattern, url, re.I):
            return platform
    return None


def _handle_from_url(url: str, platform: str) -> str | None:
    patterns = {
        "github": r"github\.com/([\w\-]+)",
        "x": r"(?:twitter|x)\.com/(?:#!\/)?([\w_]+)",
        "instagram": r"instagram\.com/([\w\.]+)",
        "linkedin": r"linkedin\.com/(?:in|pub)/([\w\-]+)",
        "facebook": r"facebook\.com/([\w\.]+)",
        "tiktok": r"tiktok\.com/@([\w\.]+)",
        "youtube": r"youtube\.com/@([\w\-]+)",
        "reddit": r"reddit\.com/u(?:ser)?/([\w\-]+)",
        "medium": r"medium\.com/@([\w\-]+)",
        "spotify": r"open\.spotify\.com/(?:artist|user|show|playlist)/([\w]+)",
        "soundcloud": r"soundcloud\.com/([\w\-]+)",
        "tiktok": r"tiktok\.com/@([\w\.]+)",
    }
    pat = patterns.get(platform)
    if not pat:
        return None
    try:
        m = re.search(pat, url, re.I)
        if not m:
            return None
        slug = m.group(1)
        return f"@{slug}" if platform not in ("linkedin",) else slug
    except Exception:
        return None


def _apply_verified_profiles(
    platforms: dict,
    social_cards: list,
    verified: list[dict],
) -> None:
    for vp in verified:
        platform = (vp.get("platform") or "").lower()
        if platform == "twitter":
            platform = "x"
        url = _abs_url(vp.get("url") or "")
        if not platform or not url:
            continue
        handle = vp.get("handle") or _handle_from_url(url, platform)
        if platform == "x":
            url = re.sub(r"https?://(?:www\.)?twitter\.com", "https://x.com", url, flags=re.I)
        if platform not in platforms:
            platforms[platform] = {"found": False, "url": None}
        platforms[platform] = {
            "found": True,
            "url": url,
            "handle": handle,
            "identity_confidence": vp.get("confidence", "medium"),
            "evidence": vp.get("evidence") or [],
            "ai_verified": True,
        }
        card = {
            "platform": platform,
            "profile_url": url,
            "url": url,
            "handle": handle,
            "bio": vp.get("bio_snippet") or "",
            "display_name": vp.get("display_name_on_profile") or "",
            "job_title": vp.get("job_title") or "",
            "location": vp.get("location") or "",
            "follower_count": vp.get("follower_count") or "",
            "linked_website": vp.get("linked_website") or "",
            "profile_image_url": vp.get("profile_image_url") or "",
            "ai_verified": True,
            "confidence": vp.get("confidence", "medium"),
        }
        if not any((c.get("profile_url") or c.get("url")) == url for c in social_cards):
            social_cards.append(card)


def _build_profile_images(social_cards: list) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    order = {"high": 0, "medium": 1, "low": 2}
    sorted_cards = sorted(
        social_cards,
        key=lambda c: order.get(str(c.get("confidence", "low")).lower(), 3),
    )
    for card in sorted_cards:
        img_url = _abs_url(card.get("profile_image_url") or "")
        if not img_url or img_url in seen:
            continue
        seen.add(img_url)
        out.append({
            "url": img_url,
            "source": card.get("profile_url") or card.get("url") or "",
            "platform": card.get("platform", ""),
            "label": "From their profile",
            "verified": True,
            "confidence": card.get("confidence", "medium"),
        })
    return out


def _apply_search_result_profiles(
    name: str,
    keywords: str,
    platforms: dict,
    social_cards: list,
    web_results: list[dict],
) -> None:
    name_tokens = {t.lower() for t in re.findall(r"[a-zA-Z0-9]+", name) if len(t) > 1}
    kw_tokens = {t.lower() for t in re.findall(r"[a-zA-Z0-9]+", keywords or "") if len(t) > 2}
    for item in (web_results or [])[:40]:
        url = _abs_url(item.get("link") or item.get("url") or "")
        if not url:
            continue
        platform = _platform_from_url(url)
        if not platform:
            continue
        haystack = " ".join([
            str(item.get("title") or ""),
            str(item.get("snippet") or ""),
            url,
        ]).lower()
        name_hits = sum(1 for t in name_tokens if t in haystack)
        kw_hits = sum(1 for t in kw_tokens if t in haystack)
        if name_hits == 0 and kw_hits == 0:
            continue
        confidence = "medium" if name_hits >= max(1, min(2, len(name_tokens))) or kw_hits else "low"
        handle = _handle_from_url(url, platform)
        if platform not in platforms:
            platforms[platform] = {"found": False, "url": None}
        existing = platforms.get(platform) or {}
        if not existing.get("found") or existing.get("identity_confidence") in ("low", None):
            platforms[platform] = {
                "found": True,
                "url": url,
                "handle": handle,
                "identity_confidence": confidence,
                "evidence": [item.get("title") or item.get("snippet") or "Search result matched the provided identity context"],
                "ai_verified": False,
            }
        if not any((c.get("profile_url") or c.get("url")) == url for c in social_cards):
            social_cards.append({
                "platform": platform,
                "profile_url": url,
                "url": url,
                "handle": handle,
                "bio": item.get("snippet") or "",
                "display_name": item.get("title") or "",
                "confidence": confidence,
                "ai_verified": False,
            })


def _dedupe_images(*groups: list[dict], limit: int = 20) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for group in groups:
        for img in group or []:
            url = _abs_url(img.get("url") or "")
            if not url or url in seen:
                continue
            seen.add(url)
            out.append({**img, "url": url})
            if len(out) >= limit:
                return out
    return out


async def _fetch_one_profile(url: str, platform: str, sem: asyncio.Semaphore) -> dict:
    from agentic_policy import extract_domain, is_allowed_target
    from http_client import get_client
    from tools.crawl_utils import rate_limit_domain

    card = {"platform": platform, "url": url, "profile_url": url}
    if not url:
        return card
    try:
        if not is_allowed_target(url):
            card["fetched_profile"] = {"status": 0, "text_snippet": None, "url": url, "blocked": True}
            return card
        domain = extract_domain(url) or ""
        if domain:
            await rate_limit_domain(domain, min_interval=0.4)
    except Exception:
        pass

    async with sem:
        try:
            client = get_client()
            r = await asyncio.wait_for(
                client.get(url, headers={"User-Agent": "AKILI-Platform/2.0"}),
                timeout=10.0,
            )
            text = r.text or ""
            title_m = re.search(r"<title>([^<]+)</title>", text[:10000], re.I)
            desc_m = re.search(
                r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)',
                text[:20000],
                re.I,
            )
            og_img = re.search(
                r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)',
                text[:30000],
                re.I,
            )
            h1_m = re.search(r"<h1[^>]*>([^<]+)</h1>", text[:20000], re.I)
            if h1_m:
                snippet = h1_m.group(1).strip()
            else:
                plain = re.sub(r"<[^>]+>", " ", text[:20000])
                snippet = " ".join(plain.split())[:600]
            card["fetched_profile"] = {
                "status": r.status_code,
                "title": title_m.group(1).strip() if title_m else None,
                "description": desc_m.group(1).strip() if desc_m else None,
                "text_snippet": snippet,
                "og_image": og_img.group(1).strip() if og_img else None,
                "url": url,
            }
        except Exception:
            card["fetched_profile"] = {"status": 0, "text_snippet": None, "url": url}
    return card


async def _fetch_all_profile_pages(urls: list[dict]) -> list[dict]:
    items = (urls or [])[:12]
    sem = asyncio.Semaphore(6)
    tasks = []
    for item in items:
        url = _abs_url(item.get("url") or item.get("profile_url") or "")
        platform = (item.get("platform") or "profile").lower()
        tasks.append(_fetch_one_profile(url or "", platform, sem))
    if not tasks:
        return []
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out = []
    for r in results:
        if isinstance(r, Exception):
            continue
        out.append(r)
    return out


async def _run_all_search_queries(queries: list[str]) -> list[dict]:
    queries = [q.strip() for q in (queries or []) if q and q.strip()][:6]
    if not queries:
        return []

    async def _one(q: str) -> list[dict]:
        try:
            results, _src = await search_with_fallback(q, 8)
            return results or []
        except Exception:
            return []

    batches = await asyncio.gather(*[_one(q) for q in queries], return_exceptions=True)
    seen: set[str] = set()
    out: list[dict] = []
    for batch in batches:
        if isinstance(batch, Exception):
            continue
        for item in batch:
            link = item.get("link") or item.get("url") or ""
            if link and link not in seen:
                seen.add(link)
                out.append(item)
    return out


async def _run_image_searches(queries: list[str]) -> list[dict]:
    queries = [q.strip() for q in (queries or []) if q and q.strip()][:4]
    if not queries:
        return []

    async def _one(q: str) -> list[dict]:
        try:
            return await serpapi_image_search(q, 8)
        except Exception:
            return []

    batches = await asyncio.gather(*[_one(q) for q in queries], return_exceptions=True)
    seen: set[str] = set()
    out: list[dict] = []
    for batch in batches:
        if isinstance(batch, Exception):
            continue
        for img in batch or []:
            url = _abs_url(img.get("url") or "")
            if url and url not in seen:
                seen.add(url)
                out.append({**img, "url": url})
                if len(out) >= 15:
                    return out
    return out[:15]


async def _check_breach_databases(name: str) -> dict:
    """Optional email breach lookup — returns empty when not configured."""
    return {}


async def _collect_async(name: str, keywords: str) -> dict[str, Any]:
    agentic_notes: list[str] = []
    raw_results: list[dict] = []
    platforms = _empty_platforms()
    social_cards: list[dict] = []
    all_urls: list[str] = []

    plan = person_agent.plan_investigation(name, keywords)
    agentic_notes.append(plan.get("investigation_summary") or "AI planned profile verification")
    profile_urls = plan.get("profile_urls_to_check") or plan.get("candidates") or []

    phase2 = await asyncio.gather(
        _fetch_all_profile_pages(profile_urls),
        _run_all_search_queries(plan.get("web_search_queries") or []),
        _run_image_searches(plan.get("image_search_queries") or []),
        _check_breach_databases(name),
        return_exceptions=True,
    )

    fetched_profiles = phase2[0] if not isinstance(phase2[0], Exception) else []
    web_results = phase2[1] if not isinstance(phase2[1], Exception) else []
    web_images = phase2[2] if not isinstance(phase2[2], Exception) else []
    breach_data = phase2[3] if not isinstance(phase2[3], Exception) else {}

    for item in web_results[:30]:
        raw_results.append({
            "title": item.get("title", ""),
            "link": item.get("link", ""),
            "snippet": item.get("snippet", ""),
        })
        if item.get("link"):
            all_urls.append(item["link"])

    candidates = fetched_profiles or []
    verification = person_agent.verify_profiles(
        name,
        keywords,
        candidates,
        web_results=web_results,
    )
    verified_list = verification.get("verified_profiles") or []
    person_overview = verification.get("person_overview") or ""
    identity_notes = verification.get("identity_notes") or ""
    best_match_confidence = verification.get("best_match_confidence") or "none"
    personal_website = verification.get("personal_website")
    news_mentions = verification.get("news_mentions") or []

    if isinstance(personal_website, dict) and not personal_website.get("url"):
        personal_website = None

    _apply_verified_profiles(platforms, social_cards, verified_list)
    _apply_search_result_profiles(name, keywords, platforms, social_cards, web_results)

    for vp in verified_list:
        u = vp.get("url")
        if u:
            all_urls.append(u)

    profile_images = _build_profile_images(social_cards)
    all_images = _dedupe_images(profile_images, web_images, limit=20)
    confidence = _confidence_breakdown(platforms, social_cards, personal_website)

    if not social_cards and not person_overview:
        person_overview = (
            "We could not find enough public information to build a profile for this person. "
            "Try adding more context like their city, employer, or profession."
        )
        identity_notes = identity_notes or (
            "Try adding a city, employer, school, username, or profession to reduce same-name matches."
        )

    return {
        "name": name,
        "keywords": keywords,
        "person_overview": person_overview,
        "best_match_confidence": best_match_confidence,
        "identity_notes": identity_notes,
        "platforms": platforms,
        "social_cards": social_cards,
        "personal_website": personal_website,
        "news_mentions": news_mentions,
        "web_images": web_images,
        "profile_images": profile_images,
        "all_images": all_images,
        "breach_data": breach_data,
        "raw_results": raw_results[:30],
        "confidence_breakdown": confidence,
        "all_urls": all_urls[:30],
        "search_source": "akili_agent",
        "agentic_notes": agentic_notes + [
            "Person scan: investigation plan → parallel fetch → content verification.",
            identity_notes,
        ],
        "investigation_plan": plan.get("investigation_summary", ""),
        "serpapi_configured": bool(os.getenv("SERPAPI_KEY")),
    }


def run_person_collect(name: str, keywords: str) -> dict[str, Any]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_collect_async(name, keywords))
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, _collect_async(name, keywords)).result(timeout=180)
