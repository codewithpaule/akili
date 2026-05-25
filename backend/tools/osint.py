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
        red_flags.append("Verified breach signal for discovered email (-10)")

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
                entry = {"found": True, "url": _abs_url(link)}
                # try to extract a canonical handle/username from the URL
                try:
                    if platform == 'github':
                        m = re.search(r'github\.com/([\w\-]+)', link, re.I)
                        if m: entry['handle'] = '@' + m.group(1)
                    elif platform == 'twitter':
                        m = re.search(r'(?:twitter|x)\.com/(?:#!\/)?([\w_]+)', link, re.I)
                        if m: entry['handle'] = '@' + m.group(1)
                    elif platform == 'instagram':
                        m = re.search(r'instagram\.com/([\w\.]+)', link, re.I)
                        if m: entry['handle'] = '@' + m.group(1)
                    elif platform == 'linkedin':
                        m = re.search(r'linkedin\.com\/(?:in|pub)\/([\w\-]+)', link, re.I)
                        if m: entry['handle'] = m.group(1)
                except Exception:
                    pass
                platforms[platform] = entry

    web_images = await serpapi_image_search(query, 12)
    img_source = "serpapi" if web_images else "none"
    if not web_images:
        _, img_source = await search_with_fallback(f"{name} images", 5)

    # Detect developer-like signals in the scraped text and keywords. Only then treat GitHub as a strong identity signal.
    dev_terms = [
        "developer",
        "software",
        "engineer",
        "programmer",
        "devops",
        "frontend",
        "backend",
        "fullstack",
        "tech lead",
    ]
    text_blob = " ".join([r.get("title", "") + " " + r.get("snippet", "") for r in raw_results]).lower() + " " + (keywords or "").lower()
    is_dev = any(t in text_blob for t in dev_terms)

    # Only query the GitHub API for usernames if GitHub-like URLs were found or content looks developer-related.
    if platforms.get("github", {}).get("found") or is_dev:
        gh_user = _extract_username(name)
        gh_profile = _github_user(gh_user)
        if gh_profile:
            username = gh_profile.get("login") or _extract_username(name)
            platforms["github"] = {"found": True, "url": _abs_url(gh_profile.get("html_url")), "handle": '@' + username}
            social_cards.append({
                "platform": "github",
                "profile_url": gh_profile.get("html_url"),
                "handle": '@' + username,
                "bio": gh_profile.get("bio") or "",
                "join_date": gh_profile.get("created_at", "")[:10],
                "activity_level": "active" if gh_profile.get("public_repos", 0) > 0 else "low",
                "repo_count": gh_profile.get("public_repos", 0),
                "languages": {},
                "followers": gh_profile.get("followers", 0),
            })

    # Ensure we include any discovered platform URLs as simple social cards
    for p, info in platforms.items():
        try:
            if not info or not info.get("found") or not info.get("url"):
                continue
            profile_url = info.get("url")
            handle = info.get("handle") or None
            # avoid duplicate entries (e.g. GitHub added above)
            if any((c.get("profile_url") or c.get("url")) == profile_url for c in social_cards):
                continue
            social_cards.append({
                "platform": p,
                "profile_url": profile_url,
                "url": profile_url,
                "handle": handle,
                "bio": "",
            })
        except Exception:
            continue

    verified_images = await _fetch_verified_profile_images(platforms)

    # Find explicit emails in search snippets and check breaches only for those exact emails.
    found_emails = []
    for item in web_results:
        emails = re.findall(r"[\w.\-]+@[\w.\-]+\.\w+", item.get("snippet", ""))
        for em in emails:
            if em not in found_emails:
                found_emails.append(em)

    breaches = []
    breach_sources = []
    if found_emails:
        for em in found_emails[:3]:
            res = await check_email_breach_async(em)
            if res.get("breaches"):
                breaches.extend(res.get("breaches", []))
                src = res.get("source") or "unknown"
                if src not in breach_sources:
                    breach_sources.append(src)

    # We only expose a breach signal (no email or name PII). The exact list of breach entries is not returned.
    breach_signal = bool(breaches)
    breach_count = len(breaches)

    confidence = _confidence_breakdown(platforms, breach_signal and [True] or [], social_cards)

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
        # Do not return email or name-linked breach entries. Only expose a privacy-safe signal.
        "breach_signal": breach_signal,
        "breach_count": breach_count,
        "breach_sources": breach_sources,
        # Backwards compatibility: do not include email/name-linked breach entries.
        "breaches": [],
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
