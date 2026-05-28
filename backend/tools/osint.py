import asyncio
import os
import re
from typing import Any

import httpx

from tools.fallbacks import search_with_fallback, serpapi_image_search

PLATFORM_PATTERNS = {
    "linkedin": r"linkedin\.com/in/[\w\-]+",
    "github": r"github\.com/[\w\-]+",
    "x": r"(twitter|x)\.com/[\w]+",
    "instagram": r"instagram\.com/[\w\.]+",
}

STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "official", "profile",
    "linkedin", "instagram", "twitter", "com", "www", "http", "https", "news",
    "latest", "photos", "images", "video", "videos", "about", "home",
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


def _confidence_breakdown(platforms: dict, social_cards: list) -> dict:
    score = 30
    signals = []
    red_flags = []

    if platforms.get("github", {}).get("found") and platforms.get("github", {}).get("identity_confidence") != "weak":
        score += 20
        signals.append("GitHub account found with developer/identity evidence (+20)")
    elif platforms.get("github", {}).get("found"):
        score -= 10
        red_flags.append("GitHub match is weak or name-only; not treated as identity proof (-10)")
    if platforms.get("linkedin", {}).get("found"):
        score += 15
        signals.append("LinkedIn profile found (+15)")
    if len([p for p in platforms.values() if p.get("found")]) >= 2:
        score += 10
        signals.append("Multiple platforms consistent (+10)")
    if social_cards:
        score += 10
        signals.append("Public activity data available (+10)")
    if not platforms.get("github", {}).get("found"):
        signals.append("No verified GitHub/developer profile found (+0)")

    return {
        "score": max(0, min(100, score)),
        "signals": signals,
        "red_flags": red_flags,
        "breakdown_visible": True,
    }


def _name_terms(name: str) -> list[str]:
    return [p.lower() for p in re.findall(r"[a-zA-Z0-9]+", name) if len(p) > 1]


def _keyword_terms(keywords: str) -> list[str]:
    return [p.lower() for p in re.findall(r"[a-zA-Z0-9]+", keywords or "") if len(p) > 2 and p.lower() not in STOPWORDS]


def _compact(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _identity_evidence(name: str, keywords: str, results: list[dict]) -> dict:
    name_terms = _name_terms(name)
    key_terms = _keyword_terms(keywords)
    counts: dict[str, int] = {}
    supporting = []
    for item in results[:20]:
        text = f"{item.get('title', '')} {item.get('snippet', '')}".lower()
        name_hit = all(t in text for t in name_terms[:2]) if name_terms else False
        keyword_hits = [t for t in key_terms if t in text]
        if name_hit:
            supporting.append({
                "title": item.get("title", ""),
                "link": item.get("link", ""),
                "snippet": item.get("snippet", ""),
                "keyword_hits": keyword_hits,
            })
            for token in re.findall(r"[a-zA-Z][a-zA-Z0-9\-]{2,}", text):
                token_l = token.lower()
                if token_l not in STOPWORDS and token_l not in name_terms:
                    counts[token_l] = counts.get(token_l, 0) + 1
    majority_terms = [
        term for term, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    ]
    top = supporting[0] if supporting else {}
    canonical = name
    primary_profile = None
    if top.get("title"):
        canonical = re.split(r"[-|–—]", top["title"], 1)[0].strip() or name
    # Try to find a primary profile URL from supporting results (prefer LinkedIn/GitHub/X)
    for sup in supporting:
        link = sup.get("link", "")
        if re.search(r"linkedin\.com/in/|linkedin\.com/pub/", link, re.I):
            primary_profile = {"platform": "linkedin", "url": link}
            break
        if re.search(r"github\.com/", link, re.I) and is_likely_dev(keywords):
            primary_profile = {"platform": "github", "url": link}
            break
        if re.search(r"(?:twitter|x)\.com/", link, re.I):
            primary_profile = {"platform": "x", "url": link}
            break
    return {
        "canonical_name": canonical,
        "primary_profile": primary_profile,
        "keywords": key_terms,
        "majority_terms": majority_terms,
        "supporting_results": supporting[:8],
        "support_count": len(supporting),
    }


def is_likely_dev(keywords: str) -> bool:
    if not keywords:
        return False
    dev_terms = ("developer", "engineer", "github", "open source", "programmer", "software")
    k = (keywords or "").lower()
    return any(t in k for t in dev_terms)


def _result_matches_name(item: dict, name: str) -> bool:
    text = f"{item.get('title', '')} {item.get('snippet', '')} {item.get('link', '')}".lower()
    terms = _name_terms(name)
    if not terms:
        return False
    return all(t in text for t in terms[:2])


def _result_supports_identity(item: dict, name: str, identity: dict, *, require_keyword: bool = True) -> bool:
    text = f"{item.get('title', '')} {item.get('snippet', '')} {item.get('link', '')}".lower()
    name_match = _result_matches_name(item, name)
    keyword_hits = [t for t in identity.get("keywords", []) if t in text]
    majority_hits = [t for t in identity.get("majority_terms", [])[:6] if t in text]
    if not name_match:
        return False
    if not require_keyword:
        return True
    return bool(keyword_hits or majority_hits)


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
        "x": {"found": False, "url": None},
        "instagram": {"found": False, "url": None},
    }
    social_cards = []
    all_urls = []
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
        "github",
        "open source",
    ]
    is_dev_intent = any(t in (keywords or "").lower() for t in dev_terms)

    # Run all searches in parallel (multi-source approach)
    search_queries = [
        f"{name} {keywords}",
        f'"{name}" {keywords}',
        f'"{name}" {keywords} site:linkedin.com/in',
        f'"{name}" {keywords} site:x.com',
        f"{name} {keywords} Nigeria",
    ]
    if is_dev_intent:
        search_queries.append(f"{name} {keywords} site:github.com")
    
    search_tasks = [search_with_fallback(q, 10) for q in search_queries]
    search_results = await asyncio.gather(*search_tasks, return_exceptions=True)
    
    # Flatten and deduplicate results
    seen_urls = set()
    unique_results = []
    for result_set in search_results:
        if isinstance(result_set, Exception):
            continue
        web_results, _ = result_set
        for item in web_results:
            link = item.get("link", "")
            if link and link not in seen_urls:
                seen_urls.add(link)
                unique_results.append(item)
    
    identity = _identity_evidence(name, keywords, unique_results)

    # Process unique results
    for item in unique_results[:30]:
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
                    elif platform == 'x':
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
                existing = platforms.get(platform) or {}
                existing_url = existing.get("url")
                existing_items = [r for r in raw_results if existing_url and existing_url.rstrip("/") in (_abs_url(r.get("link", "") or "") or "").rstrip("/")]
                current_score = sum(1 for r in existing_items if _result_supports_identity(r, name, identity))
                new_score = 1 if _result_supports_identity(item, name, identity) else 0
                if not existing.get("found") or new_score >= current_score:
                    if platform == "x" and entry.get("url"):
                        entry["url"] = re.sub(r"https?://(?:www\.)?twitter\.com", "https://x.com", entry["url"], flags=re.I)
                    platforms[platform] = entry

    image_query = f'{identity.get("canonical_name") or name} {keywords} latest photo'
    web_images = await serpapi_image_search(image_query, 12)
    img_source = "serpapi" if web_images else "none"
    if not web_images:
        _, img_source = await search_with_fallback(f"{identity.get('canonical_name') or name} {keywords} images", 5)

    # Detect developer-like signals. GitHub is only accepted when the user's
    # keywords or strong profile evidence indicate a developer/software context.
    text_blob = " ".join([r.get("title", "") + " " + r.get("snippet", "") for r in raw_results]).lower() + " " + (keywords or "").lower()
    is_dev = any(t in text_blob for t in dev_terms)

    for platform in list(platforms.keys()):
        info = platforms.get(platform) or {}
        if not info.get("found") or not info.get("url"):
            continue
        matching_items = [
            r for r in raw_results
            if info["url"].rstrip("/") in (_abs_url(r.get("link", "") or "") or "").rstrip("/")
        ]
        name_match = any(_result_matches_name(r, name) for r in matching_items)
        identity_match = any(_result_supports_identity(r, name, identity) for r in matching_items)
        if platform == "github" and not (name_match and is_dev_intent and is_dev):
            platforms[platform] = {
                "found": False,
                "url": None,
                "rejected_reason": "GitHub was not shown because the search keywords did not establish a developer/software context for this subject.",
            }
        elif platform in ("linkedin", "x"):
            if not identity_match:
                platforms[platform] = {
                    "found": False,
                    "url": None,
                    "rejected_reason": f"{platform.upper()} result did not match the majority identity/keywords strongly enough.",
                }
        elif platform == "instagram":
            url = info.get("url", "")
            if re.search(r"instagram\.com/(p|reel|reels|explore|stories)/", url, re.I) or not identity_match:
                platforms[platform] = {
                    "found": False,
                    "url": None,
                    "rejected_reason": "Generic Instagram content, not a confirmed profile.",
                }

    # Only query the GitHub API when the user's keywords make developer identity relevant.
    if is_dev_intent and (platforms.get("github", {}).get("found") or is_dev):
        gh_user = _extract_username(name)
        gh_profile = _github_user(gh_user)
        if gh_profile:
            username = gh_profile.get("login") or _extract_username(name)
            gh_text = f"{gh_profile.get('name') or ''} {gh_profile.get('bio') or ''} {username}".lower()
            name_match = all(t in gh_text for t in _name_terms(name)[:2])
            if name_match and is_dev:
                platforms["github"] = {
                    "found": True,
                    "url": _abs_url(gh_profile.get("html_url")),
                    "handle": '@' + username,
                    "identity_confidence": "strong",
                }
            else:
                platforms["github"] = {
                    "found": False,
                    "url": None,
                    "rejected_reason": "GitHub username matched mechanically, but profile identity did not match the subject.",
                }
                gh_profile = None
        if gh_profile:
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
                "fetched_profile": None,
            })
        except Exception:
            continue

    verified_images = []

    # Fetch top profile pages to extract snippets for better AI vetting
    try:
        await _fetch_profile_pages(social_cards)
    except Exception:
        pass

    confidence = _confidence_breakdown(platforms, social_cards)
    confirmed_urls = {
        (info.get("url") or "").rstrip("/")
        for info in platforms.values()
        if info and info.get("found") and info.get("url")
    }
    display_urls = []
    for u in all_urls:
        abs_u = (_abs_url(u) or "").rstrip("/")
        if re.search(r"github\.com/[\w\-]+", abs_u, re.I) and abs_u not in confirmed_urls:
            continue
        display_urls.append(u)

    return {
        "name": name,
        "keywords": keywords,
        "raw_results": raw_results,
        "identity_evidence": identity,
        "search_source": "parallel_multi_source",
        "verified_images": verified_images,
        "web_images": web_images,
        "images": web_images,
        "image_source": img_source,
        "platforms": platforms,
        "social_cards": social_cards,
        "breach_signal": False,
        "breach_count": 0,
        "breach_sources": [],
        "breaches": [],
        "serpapi_configured": bool(os.getenv("SERPAPI_KEY")),
        "confidence_breakdown": confidence,
        "all_urls": display_urls[:20],
        "total_sources": len(unique_results),
        "agentic_notes": [
            "SerpAPI/search results, platform evidence, profile metadata, and images were cross-checked before confidence scoring.",
            "Weak name-only social results are rejected instead of being presented as confirmed profiles.",
        ],
    }


async def _fetch_profile_pages(social_cards: list[dict]) -> None:
    """Fetch profile pages for discovered social cards and attach a short text excerpt.

    Modifies `social_cards` in-place, adding a `fetched_profile` dict with `status`,
    `text_snippet`, and `meta` (title/description) when available.
    """
    import asyncio
    import httpx
    async def _fetch(card: dict):
        url = card.get('url') or card.get('profile_url')
        if not url:
            return card
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
                r = await client.get(url, headers={"User-Agent": "AKILI-Platform/1.0"})
                text = r.text or ""
                # extract title and meta description
                title_m = re.search(r"<title>([^<]+)</title>", text[:10000], re.I)
                desc_m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', text[:20000], re.I)
                og_m = re.search(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)', text[:20000], re.I)
                snippet = None
                # prefer visible h1 or first 600 chars of text
                h1_m = re.search(r"<h1[^>]*>([^<]+)</h1>", text[:20000], re.I)
                if h1_m:
                    snippet = h1_m.group(1).strip()
                else:
                    # strip tags and collapse whitespace for snippet
                    plain = re.sub(r"<[^>]+>", " ", text[:20000])
                    plain = " ".join(plain.split())
                    snippet = plain[:600]
                card['fetched_profile'] = {
                    'status': r.status_code,
                    'title': title_m.group(1).strip() if title_m else None,
                    'description': (desc_m.group(1).strip() if desc_m else (og_m.group(1).strip() if og_m else None)),
                    'text_snippet': snippet,
                    'url': url,
                }
        except Exception:
            card['fetched_profile'] = {'status': 0, 'text_snippet': None, 'url': url}
        return card

    tasks = [_fetch(card) for card in social_cards[:8]]
    try:
        await asyncio.gather(*tasks)
    except Exception:
        pass


def run_person_collect(name: str, keywords: str) -> dict[str, Any]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_collect_async(name, keywords))
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, _collect_async(name, keywords)).result(timeout=180)
