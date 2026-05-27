import logging
from typing import Optional

import httpx

logger = logging.getLogger("akili.breaches")

XON_BREACHES_URL = "https://api.xposedornot.com/v1/breaches"

COUNTRY_KEYWORDS = {
    "nigeria": [
        ".ng", "nigeria", "nigerian", "lagos", "abuja",
        "gtbank", "gtco", "zenith", "firstbank", "access bank", "uba",
        "fidelity", "sterling bank", "opay", "palmpay", "cowrywise",
        "paystack", "flutterwave", "interswitch", "konga", "jumia",
        "mtn nigeria", "airtel nigeria", "glo", "9mobile",
    ],
    "africa": [
        "africa", ".ng", ".za", ".ke", ".gh", ".eg", ".ma", ".et",
        ".tz", ".ug", ".rw", ".cm", ".ci", ".sn", ".ao", ".zm",
        "nigeria", "south africa", "kenya", "ghana", "egypt", "morocco",
        "ethiopia", "tanzania", "uganda", "rwanda", "cameroon", "senegal",
    ],
}


def _flatten_breaches(data) -> list[dict]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []

    exposed = data.get("exposedBreaches")
    if isinstance(exposed, list):
        return [item for item in exposed if isinstance(item, dict)]
    if isinstance(exposed, dict):
        breaches = exposed.get("breaches_details") or exposed.get("breaches") or list(exposed.values())
        if isinstance(breaches, list):
            return [item for item in breaches if isinstance(item, dict)]

    values = []
    for value in data.values():
        if isinstance(value, dict):
            values.append(value)
        elif isinstance(value, list):
            values.extend(item for item in value if isinstance(item, dict))
    return values


def _normalize_breach(item: dict) -> dict:
    name = item.get("Breach ID") or item.get("breach") or item.get("Name") or item.get("name") or item.get("title") or "Unknown"
    domain = item.get("Domain") or item.get("domain") or item.get("site") or ""
    details = item.get("Exposure Description") or item.get("details") or item.get("Description") or item.get("description") or ""
    exposed = item.get("Exposed Data") or item.get("exposed_data") or item.get("DataClasses") or item.get("data_exposed") or []
    if isinstance(exposed, str):
        exposed = [part.strip() for part in exposed.replace(";", ",").split(",") if part.strip()]
    breached_date = item.get("Breached Date") or item.get("BreachDate") or item.get("breach_date") or item.get("date") or item.get("year") or "Unknown"
    industry = item.get("Industry") or item.get("industry") or ""
    records = item.get("Exposed Records") or item.get("records") or item.get("PwnCount") or item.get("xposed_records") or 0
    password_risk = item.get("Password Risk") or item.get("password_risk") or "Unknown"
    status = item.get("Verified") or item.get("Status") or item.get("status") or "Verified"
    logo = item.get("Logo") or item.get("logo") or ""
    safe_name = "".join(ch for ch in str(name) if ch.isalnum() or ch in ("-", "_", "."))
    return {
        "breach": str(name),
        "name": str(name),
        "domain": str(domain),
        "details": str(details),
        "exposed_data": exposed if isinstance(exposed, list) else [],
        "password_hash": bool(item.get("password_hash", False)),
        "industry": str(industry),
        "year": str(breached_date),
        "breached_date": str(breached_date),
        "records": records,
        "password_risk": str(password_risk),
        "status": str(status),
        "logo": str(logo),
        "source_link": item.get("source_link") or item.get("References") or item.get("reference") or f"https://xposedornot.com/xposed#breach-{safe_name}",
        "country_hint": _country_hint(item),
    }


def _search_blob(item: dict) -> str:
    return " ".join(
        str(item.get(k, ""))
        for k in ("breach", "name", "domain", "details", "industry", "year", "country_hint")
    ).lower()


def _country_hint(item: dict) -> str:
    blob = " ".join(str(item.get(k, "")) for k in ("domain", "breach", "name", "details", "industry")).lower()
    for country, keywords in COUNTRY_KEYWORDS.items():
        if any(keyword in blob for keyword in keywords):
            return country
    return ""


def _filter_breaches(breaches: list[dict], *, country: Optional[str] = None, q: str = "") -> list[dict]:
    country_key = (country or "").strip().lower()
    query = (q or "").strip().lower()
    out = breaches
    if country_key and country_key != "all":
        keywords = COUNTRY_KEYWORDS.get(country_key, [country_key])
        out = [item for item in out if any(keyword in _search_blob(item) for keyword in keywords)]
    if query:
        out = [item for item in out if query in _search_blob(item)]
    return out


async def get_breaches(country: Optional[str] = None, q: str = "", limit: int = 250) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(XON_BREACHES_URL, headers={"User-Agent": "AKILI-Platform/1.0"})
        if response.status_code != 200:
            logger.error("Failed to fetch breaches from XposedOrNot: status=%s", response.status_code)
            return {"breaches": [], "total": 0, "source": "xposedornot", "country": country or "all"}

        normalized = [_normalize_breach(item) for item in _flatten_breaches(response.json())]
        filtered = _filter_breaches(normalized, country=country, q=q)
        return {
            "breaches": filtered[: max(1, min(limit, 500))],
            "total": len(filtered),
            "source": "xposedornot",
            "country": country or "all",
            "query": q,
        }
    except Exception as e:
        logger.exception("Error while fetching/parsing breaches")
        return {"breaches": [], "total": 0, "source": "xposedornot", "country": country or "all", "error": str(e)}


async def get_nigeria_breaches():
    return await get_breaches(country="nigeria")
