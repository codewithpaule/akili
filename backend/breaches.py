import httpx
import logging

logger = logging.getLogger("akili.breaches")

async def get_nigeria_breaches():
    url = "https://api.xposedornot.com/v1/breaches"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                url,
                headers={
                    "User-Agent": "AKILI-Platform/1.0"
                }
            )
            if response.status_code != 200:
                logger.error("Failed to fetch breaches from XposedOrNot: status=%s", response.status_code)
                return {"breaches": [], "total": 0, "source": "xposedornot"}
            
            data = response.json()
            
            # XposedOrNot returns breaches inside an 'exposedBreaches' object
            raw_breaches = []
            if isinstance(data, dict):
                # Standard endpoint is often a dictionary with breach details
                raw_breaches = data.get("exposedBreaches", [])
                if not raw_breaches and "exposedBreaches" in data:
                    raw_breaches = data["exposedBreaches"]
                elif not raw_breaches:
                    # Let's inspect dict keys or fall back to checking entries
                    raw_breaches = list(data.values())
            elif isinstance(data, list):
                raw_breaches = data

            nigeria_keywords = [
                ".ng", "nigeria", "nigerian",
                "gtbank", "zenith", "firstbank",
                "access bank", "uba", "fidelity",
                "mtn nigeria", "airtel nigeria",
                "glo", "9mobile", "konga", "jumia",
                "flutterwave", "paystack", "piggyvest",
                "opay", "palmpay", "cowrywise"
            ]
            
            nigeria_breaches = []
            for item in raw_breaches:
                if not isinstance(item, dict):
                    continue
                
                # Check domain, breach name, or details for Nigerian keywords
                domain = str(item.get("domain", "")).lower()
                breach_name = str(item.get("breach", "")).lower()
                details = str(item.get("details", "")).lower()
                
                # ONLY matches target Nigerian infrastructure (.ng domain or specific local tech/banks)
                is_nigerian = (
                    domain.endswith(".ng") or 
                    any(f".{kw}" in domain for kw in nigeria_keywords) or
                    any(kw in domain for kw in nigeria_keywords) or
                    any(kw in breach_name for kw in nigeria_keywords)
                )
                
                if is_nigerian:
                    nigeria_breaches.append({
                        "breach": item.get("breach", "Unknown"),
                        "domain": item.get("domain", ""),
                        "details": item.get("details", ""),
                        "exposed_data": item.get("exposed_data", []),
                        "password_hash": item.get("password_hash", False),
                        "industry": item.get("industry", ""),
                        "year": item.get("year", "Unknown"),
                        "records": item.get("records", 0)
                    })
                    
            return {
                "breaches": nigeria_breaches,
                "total": len(nigeria_breaches),
                "source": "xposedornot"
            }
            
    except Exception as e:
        logger.exception("Error while fetching/parsing Nigerian breaches")
        return {"breaches": [], "total": 0, "source": "xposedornot", "error": str(e)}
