"""API fallback chains — search, CVE lookups, breach checks."""

import os
from typing import Any, Optional
from urllib.parse import quote

import httpx
from dotenv import load_dotenv

load_dotenv()

SERPAPI_KEY = os.getenv("SERPAPI_KEY", "")
HIBP_API_KEY = (os.getenv("HIBP_API_KEY", "") or "").strip()
GOOGLE_SEARCH_KEY = os.getenv("GOOGLE_SEARCH_KEY", "")
GOOGLE_SEARCH_CX = os.getenv("GOOGLE_SEARCH_CX", "")
BING_SEARCH_KEY = os.getenv("BING_SEARCH_KEY", "")


def cve_external_links(cve_id: str) -> dict[str, str]:
    """Public CVE detail pages (NVD, MITRE, CIRCL)."""
    cid = (cve_id or "").strip().upper()
    if not cid.startswith("CVE-"):
        return {"nvd": "", "mitre": "", "circl": ""}
    return {
        "nvd": f"https://nvd.nist.gov/vuln/detail/{cid}",
        "mitre": f"https://www.cve.org/CVERecord?id={cid}",
        "circl": f"https://cve.circl.lu/cve/{cid}",
    }


def get_cvss_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "none"


async def google_search(query: str, num: int = 10) -> list[dict]:
    if not GOOGLE_SEARCH_KEY or not GOOGLE_SEARCH_CX:
        return []
    url = "https://www.googleapis.com/customsearch/v1"
    params = {"key": GOOGLE_SEARCH_KEY, "cx": GOOGLE_SEARCH_CX, "q": query, "num": min(num, 10)}
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        items = data.get("items", [])
        return [
            {
                "title": i.get("title", ""),
                "link": i.get("link", ""),
                "snippet": i.get("snippet", ""),
                "displayLink": i.get("displayLink", ""),
            }
            for i in items
        ]


async def google_image_search(query: str, num: int = 10) -> list[dict]:
    if not GOOGLE_SEARCH_KEY or not GOOGLE_SEARCH_CX:
        return []
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": GOOGLE_SEARCH_KEY,
        "cx": GOOGLE_SEARCH_CX,
        "q": query,
        "searchType": "image",
        "num": min(num, 10),
    }
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        results = []
        for item in data.get("items", []):
            image = item.get("image") or {}
            results.append({
                "url": item.get("link", ""),
                "source": item.get("displayLink", ""),
                "title": item.get("title", ""),
                "thumbnail": image.get("thumbnailLink", ""),
                "context_url": image.get("contextLink", ""),
                "confidence": "unverified",
                "label": f"From {item.get('displayLink', 'web')}",
                "verified": False,
            })
        return results


async def duckduckgo_search(query: str, num: int = 10) -> list[dict]:
    url = "https://api.duckduckgo.com/"
    params = {"q": query, "format": "json", "no_redirect": 1}
    async with httpx.AsyncClient(timeout=12) as client:
        response = await client.get(url, params=params)
        if response.status_code != 200:
            return []
        data = response.json()
        results = []
        for topic in (data.get("RelatedTopics") or [])[:num]:
            if isinstance(topic, dict) and topic.get("FirstURL"):
                results.append({
                    "title": topic.get("Text", "")[:120],
                    "link": topic.get("FirstURL", ""),
                    "snippet": topic.get("Text", ""),
                    "displayLink": topic.get("FirstURL", "").split("/")[2] if topic.get("FirstURL") else "",
                })
        return results[:num]


async def bing_search(query: str, num: int = 10) -> list[dict]:
    if not BING_SEARCH_KEY:
        return []
    url = "https://api.bing.microsoft.com/v7.0/search"
    headers = {"Ocp-Apim-Subscription-Key": BING_SEARCH_KEY}
    params = {"q": query, "count": min(num, 10)}
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(url, headers=headers, params=params)
        if response.status_code != 200:
            return []
        data = response.json()
        return [
            {
                "title": w.get("name", ""),
                "link": w.get("url", ""),
                "snippet": w.get("snippet", ""),
                "displayLink": w.get("displayLink", ""),
            }
            for w in data.get("webPages", {}).get("value", [])[:num]
        ]


async def serpapi_search(query: str, engine: str = "google", num: int = 10) -> list[dict]:
    if not SERPAPI_KEY:
        return []
    from cache import cache_get, cache_set, cache_key
    from http_client import get_client

    ck = cache_key("serpapi", query, engine)
    cached = cache_get(ck)
    if cached is not None:
        return cached

    params = {
        "api_key": SERPAPI_KEY,
        "q": query,
        "engine": engine,
        "num": min(num, 10),
    }
    client = get_client()
    response = await client.get("https://serpapi.com/search", params=params)
    response.raise_for_status()
    data = response.json()
    if engine == "google_images":
        results = [
            {
                "url": img.get("original") or img.get("thumbnail"),
                "source": img.get("source") or img.get("link", ""),
                "title": img.get("title", ""),
                "thumbnail": img.get("thumbnail", ""),
                "confidence": "unverified",
                "label": f"From {img.get('source', 'SerpAPI')}",
                "verified": False,
            }
            for img in data.get("images_results", [])[:num]
        ]
    else:
        results = [
            {
                "title": item.get("title", ""),
                "link": item.get("link", ""),
                "snippet": item.get("snippet", ""),
                "displayLink": item.get("displayed_link", ""),
            }
            for item in data.get("organic_results", [])[:num]
        ]
    cache_set(ck, results, ttl_seconds=600)
    return results


async def serpapi_image_search(query: str, num: int = 10) -> list[dict]:
    return await serpapi_search(query, engine="google_images", num=num)


async def search_with_fallback(query: str, num: int = 10) -> tuple[list[dict], str]:
    try:
        results = await serpapi_search(query, "google", num)
        if results:
            return results, "serpapi"
    except Exception:
        pass
    try:
        results = await google_search(query, num)
        if results:
            return results, "google"
    except Exception:
        pass
    try:
        results = await duckduckgo_search(query, num)
        if results:
            return results, "duckduckgo"
    except Exception:
        pass
    try:
        results = await bing_search(query, num)
        if results:
            return results, "bing"
    except Exception:
        pass
    return [], "none"


async def lookup_cves_circl(product: str, version: str) -> tuple[list[dict], str]:
    product_clean = (product or "").lower().replace(" ", "-")[:80]
    version_clean = (version or "unknown")[:40]
    url = f"https://cve.circl.lu/api/search/{product_clean}/{version_clean}"
    async with httpx.AsyncClient(timeout=12) as client:
        try:
            response = await client.get(url)
            if response.status_code != 200:
                return [], "cve.circl.lu"
            data = response.json()
            if not isinstance(data, list):
                return [], "cve.circl.lu"
            cves = []
            for cve in data[:10]:
                cvss = float(cve.get("cvss", 0) or 0)
                cid = cve.get("id", "")
                links = cve_external_links(cid)
                cves.append({
                    "id": cid,
                    "summary": (cve.get("summary", "") or "")[:200],
                    "cvss": cvss,
                    "severity": get_cvss_severity(cvss),
                    "published": (cve.get("Published", "") or "")[:10],
                    "link": links["nvd"],
                    "links": links,
                })
            cves.sort(key=lambda x: x["cvss"], reverse=True)
            return cves, "cve.circl.lu"
        except Exception:
            return [], "cve.circl.lu"


async def lookup_cves_nvd(product: str, version: str, severity: str = "") -> tuple[list[dict], str]:
    keyword = f"{product} {version}".strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 10}
    if severity:
        params["cvssV3Severity"] = severity.upper()
    async with httpx.AsyncClient(timeout=20) as client:
        try:
            response = await client.get(url, params=params)
            if response.status_code != 200:
                return [], "NVD"
            data = response.json()
            cves = []
            for item in data.get("vulnerabilities", [])[:10]:
                cve = item.get("cve", {})
                cid = cve.get("id", "")
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")[:200]
                        break
                metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                cvss = 0.0
                if metrics:
                    cvss = float(metrics[0].get("cvssData", {}).get("baseScore", 0) or 0)
                links = cve_external_links(cid)
                cves.append({
                    "id": cid,
                    "summary": desc,
                    "cvss": cvss,
                    "severity": get_cvss_severity(cvss),
                    "published": (cve.get("published", "") or "")[:10],
                    "link": links["nvd"],
                    "links": links,
                })
            cves.sort(key=lambda x: x["cvss"], reverse=True)
            return cves, "NVD"
        except Exception:
            return [], "NVD"


async def lookup_cves_with_fallback(product: str, version: str) -> tuple[list[dict], str]:
    if not version:
        return [], "none"
    try:
        result, source = await lookup_cves_circl(product, version)
        if result:
            return result, source
    except Exception:
        pass
    try:
        result, source = await lookup_cves_nvd(product, version)
        return result, source
    except Exception:
        return [], "none"


def _hibp_breach_check(email: str) -> dict | None:
    """Have I Been Pwned v3 — matches haveibeenpwned.com when HIBP_API_KEY is set."""
    if not HIBP_API_KEY:
        return None
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "AKILI-Security-Platform",
    }
    try:
        with httpx.Client(timeout=15) as client:
            response = client.get(url, headers=headers)
        if response.status_code == 404:
            return {
                "found": False,
                "pwned": False,
                "breach_count": 0,
                "breaches": [],
                "source": "haveibeenpwned.com",
            }
        if response.status_code != 200:
            return None
        data = response.json()
        if not isinstance(data, list):
            return None
        breaches = []
        for b in data[:30]:
            name = b.get("Name", "Unknown")
            breaches.append({
                "name": name,
                "year": (b.get("BreachDate") or "")[:4],
                "exposed_data": b.get("DataClasses", []) or [],
                "link": f"https://haveibeenpwned.com/PwnedWebsites#{name}",
            })
        return {
            "found": True,
            "pwned": True,
            "breach_count": len(breaches),
            "breaches": breaches,
            "source": "haveibeenpwned.com (optional)",
        }
    except Exception:
        return None


def _flatten_breach_names(raw) -> list[str]:
    """XposedOrNot returns breaches as [[name1, name2, ...]] — flatten to strings."""
    names: list[str] = []
    if not raw:
        return names
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str) and item.strip():
                names.append(item.strip())
            elif isinstance(item, list):
                for sub in item:
                    if isinstance(sub, str) and sub.strip():
                        names.append(sub.strip())
    return names


def _breach_records_from_names(names: list[str], source: str) -> list[dict]:
    seen: set[str] = set()
    records = []
    for name in names:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        link = ""
        if source == "haveibeenpwned.com":
            link = f"https://haveibeenpwned.com/PwnedWebsites#{name}"
        elif "xposedornot" in source:
            link = "https://xposedornot.com/"
        records.append({
            "name": name,
            "year": "unknown",
            "exposed_data": [],
            "link": link,
        })
    return records


def _xposedornot_breach_check(email: str) -> dict:
    """Free breach API — no API key required (https://xposedornot.com)."""
    url = f"https://api.xposedornot.com/v1/check-email/{quote(email)}"
    headers = {"User-Agent": "AKILI-Platform/1.0"}
    try:
        with httpx.Client(timeout=20) as client:
            response = client.get(url, headers=headers)
        if response.status_code == 404:
            return {
                "found": False,
                "pwned": False,
                "breach_count": 0,
                "breaches": [],
                "source": "xposedornot.com (free)",
            }
        if response.status_code != 200:
            return {
                "found": False,
                "pwned": False,
                "breach_count": 0,
                "breaches": [],
                "error": f"HTTP {response.status_code}",
                "source": "xposedornot.com (free)",
            }
        data = response.json()
        names = _flatten_breach_names(data.get("breaches") or data.get("exposures") or [])
        if not names and isinstance(data.get("breaches"), list):
            for b in data["breaches"]:
                if isinstance(b, dict):
                    n = b.get("breach") or b.get("name")
                    if n:
                        names.append(str(n))
        breaches = _breach_records_from_names(names[:50], "xposedornot.com")
        return {
            "found": bool(breaches),
            "pwned": bool(breaches),
            "breach_count": len(breaches),
            "breaches": breaches,
            "source": "xposedornot.com (free)",
        }
    except Exception as e:
        return {
            "found": False,
            "pwned": False,
            "breach_count": 0,
            "breaches": [],
            "error": str(e)[:200],
            "source": "xposedornot.com (free)",
        }


def _merge_breach_results(results: list[dict]) -> dict:
    """Combine breaches from multiple free/paid sources (dedupe by name)."""
    merged: list[dict] = []
    seen: set[str] = set()
    sources: list[str] = []
    errors: list[str] = []
    for r in results:
        if not r:
            continue
        src = r.get("source", "")
        if src and src not in sources:
            sources.append(src)
        if r.get("error"):
            errors.append(str(r["error"])[:80])
        for b in r.get("breaches") or []:
            key = (b.get("name") or "").lower()
            if key and key not in seen:
                seen.add(key)
                merged.append(b)
    source_label = " + ".join(sources) if sources else "none"
    return {
        "found": bool(merged),
        "pwned": bool(merged),
        "breach_count": len(merged),
        "breaches": merged,
        "source": source_label,
        "errors": errors[:3] if errors else None,
    }


def check_email_breach(email: str) -> dict:
    """
    Sync breach lookup — no API key required by default.
    Uses XposedOrNot (free). Optional HIBP_API_KEY adds haveibeenpwned.com data.
    """
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return {"found": False, "pwned": False, "breach_count": 0, "breaches": []}

    results = [_xposedornot_breach_check(email)]
    if HIBP_API_KEY:
        hibp = _hibp_breach_check(email)
        if hibp is not None:
            results.append(hibp)
    return _merge_breach_results(results)


async def check_email_breach_async(email: str) -> dict:
    import asyncio
    return await asyncio.to_thread(check_email_breach, email)
