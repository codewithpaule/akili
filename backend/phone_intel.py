import os
import re
import time
from typing import Any, Dict, List

import httpx
from fastapi import HTTPException

from tools.fallbacks import search_with_fallback

try:
    import phonenumbers
    from phonenumbers import NumberParseException
except Exception:
    phonenumbers = None

PLATFORM_PATTERNS = {
    "linkedin": r"linkedin\.com/(in|profile)/([\w\-\.]+)",
    "github": r"github\.com/([\w\-]+)",
    "twitter": r"(twitter|x)\.com/([\w\-_]+)",
    "instagram": r"instagram\.com/([\w\.]+)",
    "facebook": r"facebook\.com/([\w\.\-]+)",
    "tiktok": r"tiktok\.com/@([\w\.\-]+)",
    "mastodon": r"(@[\w\.\-]+@[\w\.\-]+)",
    "telegram": r"t.me/([\w\-]+)|telegram\.me/([\w\-]+)",
    "pinterest": r"pinterest\.com/([\w\-_/]+)",
    "youtube": r"youtube\.com/(?:c/|user/|@)?([\w\-]+)",
    "reddit": r"reddit\.com/user/([\w\-]+)",
    "snapchat": r"snapchat\.com/add/([\w\-]+)",
}


COMMON_HANDLE_RE = re.compile(r"@([A-Za-z0-9_.\-]{2,30})")


PROFILE_URL_TEMPLATES = {
    "twitter": "https://twitter.com/{handle}",
    "instagram": "https://instagram.com/{handle}",
    "github": "https://github.com/{handle}",
    "linkedin": "https://www.linkedin.com/in/{handle}",
    "facebook": "https://facebook.com/{handle}",
    "tiktok": "https://www.tiktok.com/@{handle}",
    "telegram": "https://t.me/{handle}",
    "youtube": "https://www.youtube.com/{handle}",
    "reddit": "https://www.reddit.com/user/{handle}",
    "pinterest": "https://www.pinterest.com/{handle}",
    "snapchat": "https://www.snapchat.com/add/{handle}",
}


def normalize_phone(raw: str) -> Dict[str, Any]:
    if not raw or not str(raw).strip():
        raise HTTPException(400, "phone required")
    s = str(raw).strip()
    if phonenumbers:
        try:
            n = phonenumbers.parse(s, None)
            e164 = phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)
            country = phonenumbers.region_code_for_number(n)
            t = phonenumbers.number_type(n)
            line_type = {
                phonenumbers.NumberType.MOBILE: "mobile",
                phonenumbers.NumberType.FIXED_LINE: "landline",
                phonenumbers.NumberType.FIXED_LINE_OR_MOBILE: "mobile",
                phonenumbers.NumberType.VOIP: "voip",
            }.get(t, "unknown")
            return {"valid": True, "e164": e164, "country": country, "line_type": line_type}
        except NumberParseException:
            pass
    # Fallback naive normalization
    digits = re.sub(r"[^0-9+]", "", s)
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    if not digits.startswith("+"):
        digits = "+" + digits
    return {"valid": True, "e164": digits, "country": None, "line_type": "unknown"}


async def scan_phone(phone: str) -> Dict[str, Any]:
    # Phone scanning is disabled in this deployment per configuration.
    # The original implementation (web searches, handle extraction and
    # heuristics) has been commented out below for reference.
    norm = normalize_phone(phone)
    return {
        "phone": phone,
        "normalized": norm,
        "search_source": "disabled",
        "social_matches": [],
        "evidence": [],
        "created_at": int(time.time()),
        "note": "Phone scanning disabled; enable by restoring implementation in backend/phone_intel.py",
    }

# --- Original implementation (commented out) ---
# async def scan_phone(phone: str) -> Dict[str, Any]:
#     norm = normalize_phone(phone)
#     q = norm.get("e164") or phone
#     # Search web for exact number mentions
#     results, source = await search_with_fallback(q, 15)
#     social_matches: List[Dict[str, Any]] = []
#     links_seen = set()
#
#     def add_match(platform: str, handle: str, url: str | None, confidence: int):
#         if not handle:
#             return
#         key = f"{platform}:{handle}" if platform else f"unknown:{handle}"
#         if key in links_seen:
#             return
#         links_seen.add(key)
#         profile_url = None
#         if url and url.startswith('http'):
#             profile_url = url
#         elif platform and PROFILE_URL_TEMPLATES.get(platform):
#             profile_url = PROFILE_URL_TEMPLATES[platform].format(handle=handle)
#         social_matches.append({"platform": platform or "unknown", "handle": handle, "url": profile_url, "confidence": confidence})
#
#     # Scan links first (strong signal)
#     for item in results:
#         link = (item.get("link") or "")
#         if not link:
#             continue
#         for platform, pattern in PLATFORM_PATTERNS.items():
#             m = re.search(pattern, link, re.I)
#             if m:
#                 # pick last non-empty group as handle
#                 groups = [g for g in m.groups() if g]
#                 handle = groups[-1] if groups else None
#                 add_match(platform, handle, link, 90)
#
#     # Scan snippets and titles for explicit @handles and platform mentions
#     for item in results:
#         snippet = (item.get("snippet") or "") + " " + (item.get("title") or "")
#         if not snippet:
#             continue
#         # explicit @handle
#         for m in COMMON_HANDLE_RE.finditer(snippet):
#             h = m.group(1)
#             # Heuristic: if platform name nearby, prefer that platform
#             context_start = max(0, m.start() - 80)
#             context = snippet[context_start:m.end()+80].lower()
#             detected = None
#             for p in PLATFORM_PATTERNS.keys():
#                 if p in context:
#                     detected = p
#                     break
#             add_match(detected or "unknown", h, item.get("link"), 60 if detected else 40)
#         # domain-based mentions inside snippet
#         for platform, pattern in PLATFORM_PATTERNS.items():
#             m = re.search(pattern, snippet, re.I)
#             if m:
#                 groups = [g for g in m.groups() if g]
#                 handle = groups[-1] if groups else None
#                 add_match(platform, handle, item.get("link"), 70)
#
#     # Reduce to best confidence per platform+handle
#     best: Dict[str, Dict[str, Any]] = {}
#     for s in social_matches:
#         k = f"{s['platform']}:{s['handle']}"
#         existing = best.get(k)
#         if not existing or s['confidence'] > existing['confidence']:
#             best[k] = s
#
#     out = {
#         "phone": phone,
#         "normalized": norm,
#         "search_source": source,
#         "social_matches": list(best.values()),
#         "evidence": results[:12],
#         "created_at": int(time.time()),
#     }
#     return out
