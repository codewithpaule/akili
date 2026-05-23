import asyncio
import os
import re
from typing import Any

import httpx

from tools.fallbacks import check_email_breach_async, search_with_fallback, serpapi_image_search

PLATFORM_PATTERNS = {
    "linkedin": r"linkedin\.com/in/[\w\-]+",
    "github": r"github\.com/[\w\-]+",
    "twitter": r"(twitter|x)\.com/[\w]+",
    "instagram": r"instagram\.com/[\w\.]+",
}


def _github_user(username: str) -> dict | None:
    try:
        resp = httpx.get(f"https://api.github.com/users/{username}", timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def _extract_username(name: str) -> str:
    return re.sub(r"[^\w\-]", "", name.lower().replace(" ", ""))[:39]


async def _fetch_verified_profile_images(platforms: dict) -> list[dict]:
    verified = []
    gh = platforms.get("github", {})
    if gh.get("found") and gh.get("url"):
        m = re.search(r"github\.com/([\w\-]+)", gh["url"], re.I)
        if m:
            username = m.group(1)
            verified.append({
                "url": f"https://github.com/{username}.png",
                "source": gh["url"],
                "platform": "github",
                "label": "From GitHub",
                "verified": True,
                "confidence": "verified",
            })
    for platform, info in platforms.items():
        if platform == "github" or not info.get("found") or not info.get("url"):
            continue
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                r = await client.get(info["url"], headers={"User-Agent": "AKILI-Platform/1.0"})
                if r.status_code == 200:
                    og = re.search(
                        r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)',
                        r.text[:50000],
                        re.I,
                    )
                    if og:
                        verified.append({
                            "url": og.group(1),
                            "source": info["url"],
                            "platform": platform,
                            "label": f"From {platform.title()}",
                            "verified": True,
                            "confidence": "verified",
                        })
        except Exception:
            continue
    return verified


def _confidence_breakdown(platforms: dict, breaches: list, social_cards: list) -> dict:
    score = 30
    signals = []
    red_flags = []

    if platforms.get("github", {}).get("found"):
        score += 20
        signals.append("GitHub account found and active (+20)")
    if platforms.get("linkedin", {}).get("found"):
        score += 15
        signals.append("LinkedIn profile found (+15)")
    if len([p for p in platforms.values() if p.get("found")]) >= 2:
        score += 10
        signals.append("Multiple platforms consistent (+10)")
    if social_cards:
        score += 10
        signals.append("Public activity data available (+10)")

    if breaches:
        score -= 10
        red_flags.append("Email or name associated with breach data (-10)")

    return {
        "score": max(0, min(100, score)),
        "signals": signals,
        "red_flags": red_flags,
        "breakdown_visible": True,
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


async def _collect_async(name: str, keywords: str) -> dict[str, Any]:
    query = f"{name} {keywords}".strip()
    raw_results = []
    platforms = {
        "linkedin": {"found": False, "url": None},
        "github": {"found": False, "url": None},
        "twitter": {"found": False, "url": None},
        "instagram": {"found": False, "url": None},
    }
    social_cards = []
    all_urls = []

    web_results, search_source = await search_with_fallback(query, 10)
    for item in web_results:
        link = item.get("link", "")
        raw_results.append({
            "title": item.get("title", ""),
            "link": link,
            "snippet": item.get("snippet", ""),
        })
        all_urls.append(link)
        for platform, pattern in PLATFORM_PATTERNS.items():
            if re.search(pattern, link, re.I):
                platforms[platform] = {"found": True, "url": _abs_url(link)}

    web_images = await serpapi_image_search(query, 12)
    img_source = "serpapi" if web_images else "none"
    if not web_images:
        _, img_source = await search_with_fallback(f"{name} images", 5)

    gh_user = _extract_username(name)
    gh_profile = _github_user(gh_user)
    if gh_profile:
        platforms["github"] = {"found": True, "url": _abs_url(gh_profile.get("html_url"))}
        social_cards.append({
            "platform": "github",
            "profile_url": gh_profile.get("html_url"),
            "bio": gh_profile.get("bio") or "",
            "join_date": gh_profile.get("created_at", "")[:10],
            "activity_level": "active" if gh_profile.get("public_repos", 0) > 0 else "low",
            "repo_count": gh_profile.get("public_repos", 0),
            "languages": {},
            "followers": gh_profile.get("followers", 0),
        })

    verified_images = await _fetch_verified_profile_images(platforms)

    breaches = []
    breach_data = await check_email_breach_async(name.replace(" ", "").lower() + "@gmail.com")
    if not breach_data.get("found"):
        for item in web_results:
            emails = re.findall(r"[\w.\-]+@[\w.\-]+\.\w+", item.get("snippet", ""))
            for em in emails[:1]:
                breach_data = await check_email_breach_async(em)
                break

    if breach_data.get("breaches"):
        breaches = breach_data["breaches"]

    confidence = _confidence_breakdown(platforms, breaches, social_cards)

    return {
        "name": name,
        "keywords": keywords,
        "raw_results": raw_results,
        "search_source": search_source,
        "verified_images": verified_images,
        "web_images": web_images,
        "images": web_images,
        "image_source": img_source,
        "platforms": platforms,
        "social_cards": social_cards,
        "breaches": breaches,
        "breach_source": breach_data.get("source", "xposedornot.com"),
        "serpapi_configured": bool(os.getenv("SERPAPI_KEY")),
        "confidence_breakdown": confidence,
        "all_urls": all_urls[:20],
    }


def run_person_collect(name: str, keywords: str) -> dict[str, Any]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_collect_async(name, keywords))
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, _collect_async(name, keywords)).result(timeout=180)
