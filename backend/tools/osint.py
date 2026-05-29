import asyncio
import os
import re
from typing import Any

import httpx

from tools.fallbacks import search_with_fallback, serpapi_image_search
from tools import person_agent

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


def _platform_from_url(url: str) -> str | None:
    for platform, pattern in PLATFORM_PATTERNS.items():
        if re.search(pattern, url, re.I):
            return platform
    return None


def _handle_from_url(url: str, platform: str) -> str | None:
    try:
        if platform == "github":
            m = re.search(r"github\.com/([\w\-]+)", url, re.I)
            return f"@{m.group(1)}" if m else None
        if platform == "x":
            m = re.search(r"(?:twitter|x)\.com/(?:#!\/)?([\w_]+)", url, re.I)
            return f"@{m.group(1)}" if m else None
        if platform == "instagram":
            m = re.search(r"instagram\.com/([\w\.]+)", url, re.I)
            return f"@{m.group(1)}" if m else None
        if platform == "linkedin":
            m = re.search(r"linkedin\.com/(?:in|pub)/([\w\-]+)", url, re.I)
            return m.group(1) if m else None
    except Exception:
        pass
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
            "ai_verified": True,
            "confidence": vp.get("confidence", "medium"),
        }
        if not any((c.get("profile_url") or c.get("url")) == url for c in social_cards):
            social_cards.append(card)


async def _collect_async(name: str, keywords: str) -> dict[str, Any]:
    raw_results = []
    platforms = {
        "linkedin": {"found": False, "url": None},
        "github": {"found": False, "url": None},
        "x": {"found": False, "url": None},
        "instagram": {"found": False, "url": None},
    }
    social_cards = []
    all_urls = []
    agentic_notes = []
    dev_terms = [
        "developer", "software", "engineer", "programmer", "devops",
        "frontend", "backend", "fullstack", "tech lead", "github", "open source",
    ]
    is_dev_intent = any(t in (keywords or "").lower() for t in dev_terms)

    # AI plans the investigation (profile URLs to check, username variants)
    plan = person_agent.plan_investigation(name, keywords)
    agentic_notes.append(plan.get("investigation_summary") or "AI planned profile verification")
    candidates = plan.get("candidates") or []

    # Fetch each candidate profile page for content-based verification
    for c in candidates:
        c.setdefault("url", c.get("profile_url"))
    await _fetch_profile_pages(candidates)

    verification = person_agent.verify_profiles(name, keywords, candidates)
    verified_list = verification.get("verified_profiles") or []
    person_overview = verification.get("person_overview") or ""
    identity_notes = verification.get("identity_notes") or ""
    _apply_verified_profiles(platforms, social_cards, verified_list)

    # Fallback: only if AI found no profiles, run up to 2 AI-suggested search queries
    unique_results = []
    if not verified_list:
        queries = (plan.get("verification_queries") or [])[:2]
        if not queries:
            queries = [f'"{name}" {keywords} site:linkedin.com/in'.strip()]
        search_tasks = [search_with_fallback(q, 8) for q in queries]
        search_results = await asyncio.gather(*search_tasks, return_exceptions=True)
        seen_urls: set[str] = set()
        for result_set in search_results:
            if isinstance(result_set, Exception):
                continue
            web_results, _ = result_set
            for item in web_results:
                link = item.get("link", "")
                if link and link not in seen_urls:
                    seen_urls.add(link)
                    unique_results.append(item)
        agentic_notes.append("Supplemental search used after direct profile checks found no match")

        identity = _identity_evidence(name, keywords, unique_results)
        fallback_candidates = []
        for item in unique_results[:15]:
            link = item.get("link", "")
            raw_results.append({"title": item.get("title", ""), "link": link, "snippet": item.get("snippet", "")})
            all_urls.append(link)
            plat = _platform_from_url(link)
            if plat and _result_supports_identity(item, name, identity):
                fallback_candidates.append({
                    "platform": plat,
                    "url": _abs_url(link),
                    "reason": "search fallback",
                })
        if fallback_candidates:
            await _fetch_profile_pages(fallback_candidates)
            verification2 = person_agent.verify_profiles(name, keywords, fallback_candidates)
            _apply_verified_profiles(platforms, social_cards, verification2.get("verified_profiles") or [])
            person_overview = person_overview or verification2.get("person_overview") or ""
            identity_notes = identity_notes or verification2.get("identity_notes") or ""
    else:
        identity = _identity_evidence(name, keywords, [])
        for vp in verified_list:
            u = vp.get("url")
            if u:
                all_urls.append(u)

    # GitHub API enrichment for verified dev profiles
    gh = platforms.get("github") or {}
    if is_dev_intent and gh.get("found") and gh.get("url"):
        m = re.search(r"github\.com/([\w\-]+)", gh["url"], re.I)
        if m:
            gh_profile = _github_user(m.group(1))
            if gh_profile:
                for card in social_cards:
                    if card.get("platform") == "github":
                        card.update({
                            "bio": gh_profile.get("bio") or card.get("bio", ""),
                            "join_date": (gh_profile.get("created_at") or "")[:10],
                            "repo_count": gh_profile.get("public_repos", 0),
                            "followers": gh_profile.get("followers", 0),
                        })

    image_query = f"{name} {keywords} photo".strip()
    web_images = await serpapi_image_search(image_query, 12)
    img_source = "google_images" if web_images else "none"

    confidence = _confidence_breakdown(platforms, social_cards)
    if not social_cards:
        person_overview = person_overview or (
            "No public profile could be verified with enough confidence from the available search and profile evidence."
        )
        identity_notes = identity_notes or "Try adding a city, employer, school, username, or profession to reduce same-name matches."
    if verified_list:
        confidence["score"] = min(100, confidence["score"] + 15)
        confidence["signals"].append("AI verified profile page content (+15)")
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
        "search_source": "ai_agent",
        "person_overview": person_overview,
        "identity_notes": identity_notes,
        "investigation_plan": plan.get("investigation_summary", ""),
        "verified_images": [],
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
        "agentic_notes": agentic_notes + [
            "Person scan is AI-led: investigation plan → profile fetch → content verification.",
            "Social handles are shown only after AI confirms page content matches the subject.",
            identity_notes,
        ],
    }


async def _fetch_profile_pages(social_cards: list[dict]) -> None:
    """Fetch profile pages for discovered social cards and attach a short text excerpt.

    Modifies `social_cards` in-place, adding a `fetched_profile` dict with `status`,
    `text_snippet`, and `meta` (title/description) when available.
    """
    import asyncio
    import httpx
    from agentic_policy import is_allowed_target, extract_domain
    from tools.crawl_utils import rate_limit_domain
    async def _fetch(card: dict):
        url = card.get('url') or card.get('profile_url')
        if not url:
            return card
        # Enforce agentic policy and per-domain rate limits
        try:
            if not is_allowed_target(url):
                card['fetched_profile'] = {'status': 0, 'text_snippet': None, 'url': url, 'blocked': True}
                return card
            domain = extract_domain(url) or ''
            if domain:
                await rate_limit_domain(domain, min_interval=0.6)
        except Exception:
            pass
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
