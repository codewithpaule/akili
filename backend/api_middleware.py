import hashlib
from datetime import datetime, timedelta
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


PUBLIC_PATH_PREFIXES = (
    "/api/v1/auth/",
    "/api/v1/public/",
    "/api/v1/scan/",
)

PUBLIC_PATHS = {
    "/",
    "/api/v1/health",
    "/api/v1/breaches",
    "/api/v1/breaches/nigeria",
    "/api/v1/public-config",
    "/api/v1/billing/pricing",
    "/api/v1/plans",
}


def should_skip_api_key_validation(request: Request) -> bool:
    """Return True for routes whose handler/dependencies own auth, or public routes."""
    path = str(request.url.path)
    if request.method == "OPTIONS":
        return True
    if request.headers.get("Authorization") or request.headers.get("X-Session-Token"):
        return True
    if path in PUBLIC_PATHS:
        return True
    if any(path.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES):
        return True
    if "/health" in path:
        return True
    return False


def get_reset_timestamp() -> int:
    """Get the timestamp for the next hour reset."""
    now = datetime.utcnow()
    next_hour = (now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1))
    return int(next_hour.timestamp())


async def get_api_key(key_hash: str) -> dict:
    """Look up API key by hash with retry logic for connection errors."""
    from database import get_db, ApiKey
    import time
    
    max_retries = 2
    for attempt in range(max_retries):
        try:
            with get_db() as db:
                row = db.query(ApiKey).filter(ApiKey.key_hash == key_hash).first()
                if not row:
                    return None
                return {
                    "key_id": row.key_id,
                    "user_id": row.user_id,
                    "key_name": row.key_name,
                    "tier": row.tier,
                    "is_active": row.is_active,
                    "requests_today": row.requests_today,
                    "limit": 50 if row.tier == "free" else 500 if row.tier == "pro" else 2000
                }
        except Exception as e:
            if attempt < max_retries - 1 and ("SSL connection" in str(e) or "connection" in str(e).lower()):
                time.sleep(0.1 * (attempt + 1))
                continue
            raise
    return None


async def get_user(user_id: str) -> dict:
    """Get user by ID."""
    from database import get_db, User
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id).first()
        if not row:
            return None
        return {
            "user_id": row.user_id,
            "email": row.email,
            "usage_identity": getattr(row, "usage_identity", None) or "email:" + hashlib.sha256((row.email or "").strip().lower().encode("utf-8")).hexdigest(),
            "is_active": row.is_active,
            "email_verified": row.email_verified,
            "plan": row.plan
        }


async def get_api_usage_today(key_id: str) -> int:
    """Get today's usage for an API key."""
    from database import get_db, ApiKey
    with get_db() as db:
        row = db.query(ApiKey).filter(ApiKey.key_id == key_id).first()
        if not row:
            return 0
        return row.requests_today or 0


async def update_key_last_used(key_id: str):
    """Update the last used timestamp for an API key."""
    import time
    from database import get_db, ApiKey
    with get_db() as db:
        row = db.query(ApiKey).filter(ApiKey.key_id == key_id).first()
        if row:
            row.last_used = int(time.time())


async def validate_api_request(request: Request, call_next):
    """Sharp API key validation middleware for all /api/v1/* routes except public and health."""
    if should_skip_api_key_validation(request):
        return await call_next(request)
    
    api_key = request.headers.get("X-API-Key") or request.headers.get("x-api-key")
    
    # No key provided
    if not api_key:
        return JSONResponse(
            status_code=401,
            content={
                "error": "missing_api_key",
                "message": "X-API-Key header is required",
                "get_key": "akili.com.ng/developer"
            }
        )
    
    # Hash and look up
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    db_key = await get_api_key(key_hash)
    
    # Key not found
    if not db_key:
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_api_key",
                "message": "API key is invalid or has been revoked",
                "get_key": "akili.com.ng/developer"
            }
        )
    
    # Key inactive
    if not db_key["is_active"]:
        return JSONResponse(
            status_code=401,
            content={
                "error": "revoked_api_key",
                "message": "This API key has been revoked"
            }
        )
    
    # User check
    user = await get_user(db_key["user_id"])
    
    if not user:
        return JSONResponse(
            status_code=401,
            content={
                "error": "user_not_found",
                "message": "No user associated with this API key"
            }
        )
    
    if not user["is_active"]:
        return JSONResponse(
            status_code=403,
            content={
                "error": "account_suspended",
                "message": "This account has been suspended"
            }
        )
    
    if not user["email_verified"]:
        return JSONResponse(
            status_code=403,
            content={
                "error": "email_not_verified",
                "message": "Please verify your email address first"
            }
        )
    
    # Rate limit check
    limit = db_key["limit"]
    used = await get_api_usage_today(db_key["key_id"])
    
    if used >= limit:
        reset = get_reset_timestamp()
        return JSONResponse(
            status_code=429,
            content={
                "error": "rate_limit_exceeded",
                "message": f"Daily API limit of {limit} requests exceeded",
                "limit": limit,
                "used": used,
                "reset_at": reset,
                "upgrade": "akili.com.ng/pricing"
            },
            headers={
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset),
                "Retry-After": "3600"
            }
        )
    
    # Daily scan limit check
    from database import get_daily_scan_count
    from plans import ACCOUNT_DAILY_SCAN_LIMIT
    scan_count = get_daily_scan_count(user.get("usage_identity") or user["user_id"])
    if scan_count >= ACCOUNT_DAILY_SCAN_LIMIT:
        from database import get_midnight_utc
        return JSONResponse(
            status_code=429,
            content={
                "error": "daily_scan_limit",
                "message": f"{ACCOUNT_DAILY_SCAN_LIMIT} daily account scans used. Resets at midnight UTC.",
                "used": scan_count,
                "limit": ACCOUNT_DAILY_SCAN_LIMIT,
                "resets_at": get_midnight_utc()
            }
        )
    
    # All good — attach user to request
    request.state.user = user
    request.state.api_key = db_key
    
    # Update last used
    await update_key_last_used(db_key["key_id"])
    
    response = await call_next(request)
    
    # Add rate limit headers to response
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(limit - used - 1)
    response.headers["X-RateLimit-Reset"] = str(get_reset_timestamp())
    response.headers["X-Scans-Used-Today"] = str(scan_count + 1)
    response.headers["X-Scans-Remaining"] = str(ACCOUNT_DAILY_SCAN_LIMIT - scan_count - 1)
    
    return response


class APIKeyValidationMiddleware(BaseHTTPMiddleware):
    """Middleware to validate API keys for protected routes."""
    
    async def dispatch(self, request: Request, call_next):
        if should_skip_api_key_validation(request):
            return await call_next(request)
        
        return await validate_api_request(request, call_next)
