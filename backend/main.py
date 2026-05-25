import logging
import os
import time
import uuid
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from agent import check_groq_health, run_agent
from api_keys import generate_api_key, list_keys_for_user, lookup_api_key, revoke_key
from auth_service import (
    admin_login,
    get_current_user,
    get_current_user_from_request,
    google_login,
    login_user,
    delete_user_account,
    patch_user_profile,
    register_user,
    request_password_reset,
    reset_password_with_token,
    verify_email_token,
    require_admin,
    require_user,
    upgrade_user_premium,
)
from usage_guard import enforce_scan_access, usage_payload
from scan_profile import tier_for_user
from database import (
    create_domain_verification,
    delete_all_scans,
    delete_monitor,
    delete_scan,
    enable_report_share,
    get_agency_profile,
    get_report_by_share_token,
    get_domain_verification,
    get_finding_status,
    get_report,
    get_score_history,
    list_history,
    list_monitor_alerts,
    list_monitors,
    mark_domain_verified,
    remediation_progress,
    save_agency_profile,
    save_contact,
    save_monitor,
    upsert_finding_status,
)
from scan_templates import run_template
from tools.auth_scan import run_auth_scan
from tools.api_scanner import scan_api
from tools.verify_domain import check_txt_record, generate_token
from rate_limit import get_tier_from_request, limiter, rate_limit_headers
from sandbox import get_mock_report, stream_sandbox
from security import (
    MAX_BODY_BYTES,
    validate_company,
    validate_domain,
    validate_email,
    validate_org,
    validate_person,
    validate_public_ip,
    validate_url,
)

load_dotenv()

origins_raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:5501")
ALLOWED_ORIGINS = [o.strip() for o in origins_raw.split(",") if o.strip()]

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("akili.api")


def log_scan(scan_id: str, scan_type: str):
    logger.info("scan_event scan_id=%s timestamp=%s scan_type=%s", scan_id, int(time.time()), scan_type)


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=()",
}


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            cl = request.headers.get("content-length")
            if cl and int(cl) > MAX_BODY_BYTES:
                return JSONResponse({"detail": "Request body too large (max 1MB)"}, status_code=413)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        tier, limit, _ = get_tier_from_request(request)
        remaining = max(0, limit - 1)
        for k, v in rate_limit_headers(tier, limit, remaining).items():
            response.headers[k] = v
        return response


app = FastAPI(title="AKILI API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, lambda r, e: JSONResponse({
    "error": "rate_limit_exceeded",
    "message": "You have exceeded your rate limit",
    "upgrade_url": "https://akili.io/developer",
}, status_code=429))

app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "X-Request-ID", "Authorization", "X-Session-Token"],
)


def _guard(request: Request, module: str, *, sandbox: bool = False):
    # Allow either a valid session token or a valid API key (or both).
    user = get_current_user_from_request(request)
    api_key_header = request.headers.get("X-API-Key") or request.headers.get("x-api-key")
    api_info = None
    if api_key_header:
        # check key existence without incrementing first
        api_info = lookup_api_key(api_key_header, increment_usage=False)
        if not api_info:
            # explicit invalid key provided — log and block the request
            try:
                from audit_log import log_from_request
                masked = (api_key_header[:6] + "…" + api_key_header[-6:]) if len(api_key_header) > 12 else api_key_header
                log_from_request(request, "auth.api_key.invalid", detail=f"invalid_api_key={masked}")
            except Exception:
                pass
            raise HTTPException(403, "Invalid API key")

    # If both provided, ensure they belong to the same user
    if api_info and user and api_info.get("user_id") and user.get("user_id") != api_info.get("user_id"):
        try:
            from audit_log import log_from_request
            masked = (api_key_header[:6] + "…" + api_key_header[-6:]) if len(api_key_header) > 12 else api_key_header
            log_from_request(request, "auth.api_key.mismatch", user=user, detail=f"user_id={user.get('user_id')} key_id={api_info.get('key_id')} key_preview={masked}")
        except Exception:
            pass
        raise HTTPException(403, "API key does not match authenticated user")

    if not user and api_info:
        # load the user that owns this API key
        from auth_service import get_user_by_id

        user = get_user_by_id(api_info.get("user_id") or "")
        if not user:
            try:
                from audit_log import log_from_request
                log_from_request(request, "auth.api_key.owner_not_found", detail=f"key_id={api_info.get('key_id')}")
            except Exception:
                pass
            raise HTTPException(401, "API key owner not found")

    if not user:
        raise HTTPException(401, "Sign in required or provide a valid API key")

    # Enforce per-user module access and monthly caps
    enforce_scan_access(user, module, sandbox=sandbox)

    # If request used an API key, increment usage now that it is authorized
    if api_info:
        api_info = lookup_api_key(api_key_header, increment_usage=True)
        limit = int(api_info.get("limit") or 0)
        used_today = int(api_info.get("requests_today") or 0)
        if limit and used_today > limit:
            try:
                from audit_log import log_from_request
                log_from_request(request, "auth.api_key.quota_exceeded", user=user, detail=f"key_id={api_info.get('key_id')} used_today={used_today} limit={limit}")
            except Exception:
                pass
            raise HTTPException(429, "API key hourly limit exceeded")

    return user


@app.middleware("http")
async def track_api_key_usage(request: Request, call_next):
    # Do not increment API-key usage globally here — usage is counted in `_guard`.
    return await call_next(request)


class UrlBody(BaseModel):
    url: str = Field(..., max_length=500)


class ApiScanBody(BaseModel):
    url: str = Field(..., max_length=500)
    methods: Optional[list[str]] = None
    headers: Optional[dict] = None
    form_payload: Optional[dict] = None
    auth: Optional[dict] = None
    timeout: Optional[int] = Field(default=8)
    diff: Optional[bool] = Field(default=True)


class DomainBody(BaseModel):
    domain: str = Field(..., max_length=253)


class IpBody(BaseModel):
    ip: str = Field(..., max_length=45)


class PersonBody(BaseModel):
    name: str = Field(..., max_length=100)
    keywords: str = Field(default="", max_length=200)


class OrgBody(BaseModel):
    name: str = Field(default="", max_length=200)
    domain: str = Field(default="", max_length=253)


class EmailBody(BaseModel):
    email: str = Field(..., max_length=254)


class ContactBody(BaseModel):
    name: str = Field(..., max_length=100)
    email: str = Field(..., max_length=200)
    subject: str = Field(..., max_length=200)
    message: str = Field(..., max_length=5000)


class KeyGenBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    tier: str = Field(default="free")
    sandbox: bool = Field(default=False)


class CheckoutBody(BaseModel):
    plan_id: str = Field(default="premium_monthly", max_length=40)
    return_page: str = Field(default="dashboard.html", max_length=80)


class DeleteAccountBody(BaseModel):
    password: str = Field(default="", max_length=128)
    confirmation: str = Field(..., min_length=4, max_length=20)


class RegisterBody(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(default="", max_length=128)
    name: str = Field(default="", max_length=120)
    phone: str = Field(default="", max_length=40)


class ProfilePatchBody(BaseModel):
    name: str = Field(default="", max_length=120)
    phone: str = Field(default="", max_length=40)
    organization: str = Field(default="", max_length=200)
    job_title: str = Field(default="", max_length=120)
    country: str = Field(default="", max_length=80)


class LoginBody(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., max_length=128)


class AdminUserPatchBody(BaseModel):
    name: str = Field(default="", max_length=120)
    plan: str = Field(default="", max_length=30)
    role: str = Field(default="", max_length=20)
    is_active: Optional[bool] = None
    trial_ends_at: Optional[int] = None
    subscription_status: str = Field(default="", max_length=40)
    premium_until: Optional[int] = None
    phone: str = Field(default="", max_length=40)
    organization: str = Field(default="", max_length=200)


class AdminPasswordBody(BaseModel):
    password: str = Field(..., min_length=8, max_length=128)


class AdminPlanBody(BaseModel):
    plan_id: str = Field(default="premium_monthly", max_length=40)


class AdminManualVerifyBody(BaseModel):
    reference: str = Field(..., min_length=1, max_length=80)
    user_email: str = Field(..., min_length=3, max_length=254)


class ReviewMarkBody(BaseModel):
    note: str = Field(default="", max_length=2000)


class AdminLoginBody(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., max_length=128)
    admin_pin: str = Field(default="", max_length=32)


class GoogleAuthBody(BaseModel):
    id_token: str = Field(..., max_length=8000)


class ForgotPasswordBody(BaseModel):
    email: str = Field(..., max_length=254)


class ResetPasswordBody(BaseModel):
    token: str = Field(..., min_length=20, max_length=200)
    password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(default="", max_length=128)


class MonitorBody(BaseModel):
    target: str = Field(..., max_length=500)
    target_type: str = Field(..., max_length=50)
    frequency: str = Field(default="weekly")
    alert_email: str = Field(default="", max_length=200)


class VerifyDomainBody(BaseModel):
    domain: str = Field(..., max_length=253)


class TemplateScanBody(BaseModel):
    template: str = Field(..., max_length=50)
    target: str = Field(..., max_length=500)


class FindingPatchBody(BaseModel):
    status: str = Field(..., max_length=30)
    note: str = Field(default="", max_length=2000)
    domain: str = Field(default="", max_length=253)
    finding_title: str = Field(default="Finding", max_length=500)
    scan_id: str = Field(default="", max_length=36)
    severity: str = Field(default="medium", max_length=20)


class AgencyProfileBody(BaseModel):
    company_name: str = Field(default="", max_length=200)
    logo_base64: str = Field(default="", max_length=500000)
    primary_color: str = Field(default="#2563EB", max_length=20)
    contact_email: str = Field(default="", max_length=200)
    website: str = Field(default="", max_length=300)


class AuthScanBody(BaseModel):
    url: str = Field(..., max_length=500)
    auth_type: str = Field(default="form")
    credentials: dict = Field(default_factory=dict)
    depth: str = Field(default="standard")
    authorized: bool = Field(default=False)


def _stream_agent(module: str, target: str, scan_id: str, user_id: str = "", scan_tier: str = "trial"):
    async def gen():
        for chunk in run_agent(module, target, scan_id, user_id=user_id, scan_tier=scan_tier):
            yield chunk
    return StreamingResponse(
        gen(),
        media_type="text/plain",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _require_json(request: Request):
    ct = request.headers.get("content-type", "")
    if request.method == "POST" and "application/json" not in ct:
        raise HTTPException(415, "Content-Type must be application/json")


@app.get("/api/v1/health")
@limiter.limit("60/minute")
async def health(request: Request):
    ok, detail = check_groq_health()
    return {
        "status": "ok",
        "api": "live",
        "groq": "connected" if ok else "disconnected",
        "groq_detail": detail or None,
    }


@app.post("/api/v1/auth/register")
@limiter.limit("30/hour")
async def auth_register(request: Request, body: RegisterBody):
    from audit_log import log_from_request
    _require_json(request)
    out = register_user(
        body.email, body.password, body.name, body.confirm_password, phone=body.phone
    )
    log_from_request(
        request, "user.signup", user=out.get("user"),
        resource_type="user", resource_id=out.get("user", {}).get("user_id", ""),
        detail=f"email={body.email}",
    )
    return out


@app.post("/api/v1/auth/login")
@limiter.limit("60/hour")
async def auth_login(request: Request, body: LoginBody):
    from audit_log import log_from_request
    _require_json(request)
    out = login_user(body.email, body.password)
    log_from_request(request, "user.login", user=out.get("user"), detail=f"email={body.email}")
    return out


@app.post("/api/v1/auth/google")
@limiter.limit("60/hour")
async def auth_google(request: Request, body: GoogleAuthBody):
    _require_json(request)
    return google_login(body.id_token)


@app.post("/api/v1/auth/forgot-password")
@limiter.limit("10/hour")
async def auth_forgot_password(request: Request, body: ForgotPasswordBody):
    _require_json(request)
    return request_password_reset(body.email)


@app.post("/api/v1/auth/reset-password")
@limiter.limit("20/hour")
async def auth_reset_password(request: Request, body: ResetPasswordBody):
    _require_json(request)
    if body.confirm_password and body.password != body.confirm_password:
        raise HTTPException(400, "Passwords do not match")
    return reset_password_with_token(body.token, body.password)


@app.get("/api/v1/auth/verify-email")
@limiter.limit("30/hour")
async def auth_verify_email(request: Request, token: str):
    return verify_email_token(token)


@app.post("/api/v1/cron/renewal-reminders")
async def cron_renewal_reminders(request: Request):
    from cron_jobs import run_renewal_reminder_batch, verify_cron_secret
    secret = request.headers.get("x-cron-secret", "")
    if not verify_cron_secret(secret):
        raise HTTPException(401, "Invalid cron secret")
    return run_renewal_reminder_batch()


@app.get("/api/v1/auth/google-setup")
@limiter.limit("120/minute")
async def auth_google_setup(request: Request):
    """Hints for fixing Google Error 401 invalid_client (GIS / Cloud Console)."""
    from auth_service import GOOGLE_CLIENT_ID

    origin = request.headers.get("origin") or ""
    configured = bool(GOOGLE_CLIENT_ID)
    return {
        "configured": configured,
        "client_id_prefix": GOOGLE_CLIENT_ID[:12] + "…" if configured else None,
        "request_origin": origin or None,
        "authorized_origins_to_add": [
            "http://localhost:5501",
            "http://127.0.0.1:5501",
        ],
        "steps": [
            "Google Cloud Console → APIs & Services → Credentials",
            "Create OAuth 2.0 Client ID → Application type: Web application (not Desktop)",
            "Authorized JavaScript origins: http://localhost:5501 and http://127.0.0.1:5501",
            "Copy Client ID into backend/.env GOOGLE_CLIENT_ID and frontend/js/config.js (must match exactly)",
            "Open login via http://localhost:5501/login.html (not file://)",
        ],
    }


@app.get("/api/v1/auth/me")
@limiter.limit("120/minute")
async def auth_me(request: Request, user: dict = Depends(require_user)):
    return {"user": user, "usage": usage_payload(user)}


@app.get("/api/v1/auth/check-access")
@limiter.limit("60/minute")
async def auth_check_access(request: Request, module: str = ""):
    """Return whether the current requester may run `module` scans.
    Works for bearer tokens or API keys. If not allowed, returns allowed=false
    with a message explaining the reason.
    """
    try:
        user = get_current_user_from_request(request)
        # enforce_scan_access will raise HTTPException on denial
        enforce_scan_access(user, module, sandbox=False)
        return {"allowed": True}
    except HTTPException as e:
        msg = str(e.detail) if getattr(e, 'detail', None) else 'Access denied'
        return {"allowed": False, "message": msg}


@app.get("/api/v1/auth/profile")
@limiter.limit("120/minute")
async def auth_profile_get(request: Request, user: dict = Depends(require_user)):
    return {"user": user}


@app.patch("/api/v1/auth/profile")
@limiter.limit("30/hour")
async def auth_profile_patch(request: Request, body: ProfilePatchBody, user: dict = Depends(require_user)):
    _require_json(request)
    fields = body.model_dump(exclude_unset=True)
    if not fields:
        return {"user": user}
    updated = patch_user_profile(
        user["user_id"],
        name=fields.get("name", user.get("name", "")),
        phone=fields.get("phone", user.get("phone", "")),
        organization=fields.get("organization", user.get("organization", "")),
        job_title=fields.get("job_title", user.get("job_title", "")),
        country=fields.get("country", user.get("country", "")),
    )
    return {"user": updated}


@app.delete("/api/v1/auth/account")
@limiter.limit("5/hour")
async def auth_delete_account(request: Request, body: DeleteAccountBody, user: dict = Depends(require_user)):
    _require_json(request)
    if body.confirmation.strip().upper() != "DELETE":
        raise HTTPException(400, 'Type DELETE in the confirmation field')
    delete_user_account(user["user_id"], body.password)
    return {"deleted": True, "message": "Account deleted"}


@app.get("/api/v1/auth/usage")
@limiter.limit("120/minute")
async def auth_usage(request: Request, user: dict = Depends(require_user)):
    return usage_payload(user)


# --- Admin (requires role=admin) ---


@app.post("/api/v1/admin/login")
@limiter.limit("30/hour")
async def admin_auth_login(request: Request, body: AdminLoginBody):
    from audit_log import log_from_request
    _require_json(request)
    out = admin_login(body.email, body.password, body.admin_pin)
    log_from_request(request, "admin.login", admin_user=out.get("user"), detail="Admin signed in")
    return out


@app.get("/api/v1/admin/me")
@limiter.limit("120/minute")
async def admin_me(request: Request, user: dict = Depends(require_admin)):
    return {"user": user}


@app.get("/api/v1/admin/dashboard")
@limiter.limit("120/minute")
async def admin_dashboard(request: Request, user: dict = Depends(require_admin)):
    from admin_service import admin_charts_data, admin_dashboard_stats, paystack_admin_status
    return {
        "stats": admin_dashboard_stats(),
        "billing": paystack_admin_status(),
        "charts": admin_charts_data(),
    }


@app.get("/api/v1/admin/charts")
@limiter.limit("120/minute")
async def admin_charts(request: Request, user: dict = Depends(require_admin)):
    from admin_service import admin_charts_data
    return admin_charts_data()


@app.get("/api/v1/admin/users")
@limiter.limit("120/minute")
async def admin_users_list(
    request: Request,
    page: int = 1,
    limit: int = 25,
    q: Optional[str] = None,
    plan: Optional[str] = None,
    role: Optional[str] = None,
    user: dict = Depends(require_admin),
):
    from admin_service import list_users_admin
    return list_users_admin(page=page, limit=limit, q=q or "", plan=plan or "", role=role or "")


@app.get("/api/v1/admin/users/{user_id}")
@limiter.limit("120/minute")
async def admin_user_get(request: Request, user_id: str, user: dict = Depends(require_admin)):
    from admin_service import get_user_admin
    return get_user_admin(user_id)


@app.patch("/api/v1/admin/users/{user_id}")
@limiter.limit("60/hour")
async def admin_user_patch(
    request: Request, user_id: str, body: AdminUserPatchBody, user: dict = Depends(require_admin)
):
    from admin_service import update_user_admin
    from audit_log import log_from_request
    _require_json(request)
    fields = {k: v for k, v in body.model_dump().items() if v is not None and v != ""}
    if body.is_active is not None:
        fields["is_active"] = body.is_active
    if not fields:
        from admin_service import get_user_admin
        return get_user_admin(user_id)
    out = update_user_admin(user_id, fields)
    log_from_request(
        request, "admin.user.update", admin_user=user,
        resource_type="user", resource_id=user_id, detail=str(fields)[:500],
    )
    return out


@app.post("/api/v1/admin/users/{user_id}/password")
@limiter.limit("20/hour")
async def admin_user_password(
    request: Request, user_id: str, body: AdminPasswordBody, user: dict = Depends(require_admin)
):
    from admin_service import admin_set_password
    _require_json(request)
    admin_set_password(user_id, body.password)
    return {"updated": True}


@app.post("/api/v1/admin/users/{user_id}/plan")
@limiter.limit("30/hour")
async def admin_user_plan(
    request: Request, user_id: str, body: AdminPlanBody, user: dict = Depends(require_admin)
):
    from admin_service import admin_upgrade_user
    _require_json(request)
    return admin_upgrade_user(user_id, body.plan_id)


@app.delete("/api/v1/admin/users/{user_id}")
@limiter.limit("20/hour")
async def admin_user_delete(
    request: Request, user_id: str, hard: bool = False, user: dict = Depends(require_admin)
):
    from admin_service import deactivate_user_admin
    from audit_log import log_from_request
    out = deactivate_user_admin(user_id, hard_delete=hard)
    log_from_request(
        request, "admin.user.deactivate", admin_user=user,
        resource_type="user", resource_id=user_id, detail=f"hard={hard}",
    )
    return out


@app.get("/api/v1/admin/scans")
@limiter.limit("120/minute")
async def admin_scans_list(
    request: Request,
    page: int = 1,
    limit: int = 30,
    q: Optional[str] = None,
    type: Optional[str] = None,
    user_id: Optional[str] = None,
    user: dict = Depends(require_admin),
):
    from admin_service import list_scans_admin
    return list_scans_admin(page=page, limit=limit, q=q or "", scan_type=type or "", user_id=user_id or "")


@app.delete("/api/v1/admin/scans/{scan_id}")
@limiter.limit("60/hour")
async def admin_scan_delete(request: Request, scan_id: str, user: dict = Depends(require_admin)):
    from admin_service import delete_scan_admin
    return delete_scan_admin(scan_id)


@app.get("/api/v1/admin/keys")
@limiter.limit("120/minute")
async def admin_keys_list(
    request: Request,
    page: int = 1,
    limit: int = 30,
    user_id: Optional[str] = None,
    user: dict = Depends(require_admin),
):
    from admin_service import list_keys_admin
    return list_keys_admin(page=page, limit=limit, user_id=user_id or "")


@app.delete("/api/v1/admin/keys/{key_id}")
@limiter.limit("60/hour")
async def admin_key_revoke(request: Request, key_id: str, user: dict = Depends(require_admin)):
    from admin_service import revoke_key_admin
    return revoke_key_admin(key_id)


@app.get("/api/v1/admin/contacts")
@limiter.limit("120/minute")
async def admin_contacts_list(
    request: Request, page: int = 1, limit: int = 30, user: dict = Depends(require_admin)
):
    from admin_service import list_contacts_admin
    return list_contacts_admin(page=page, limit=limit)


@app.get("/api/v1/admin/monitors")
@limiter.limit("120/minute")
async def admin_monitors_list(request: Request, user: dict = Depends(require_admin)):
    from admin_service import list_monitors_admin
    return list_monitors_admin()


@app.delete("/api/v1/admin/monitors/{monitor_id}")
@limiter.limit("30/hour")
async def admin_monitor_delete(request: Request, monitor_id: str, user: dict = Depends(require_admin)):
    if not delete_monitor(monitor_id):
        raise HTTPException(404, "Monitor not found")
    return {"deleted": True}


@app.get("/api/v1/admin/audit-logs")
@limiter.limit("120/minute")
async def admin_audit_logs(
    request: Request,
    page: int = 1,
    limit: int = 50,
    q: Optional[str] = None,
    action: Optional[str] = None,
    user: dict = Depends(require_admin),
):
    from audit_log import list_audit_logs
    return list_audit_logs(page=page, limit=limit, q=q or "", action=action or "")


@app.get("/api/v1/admin/review/scans")
@limiter.limit("120/minute")
async def admin_review_scans(request: Request, page: int = 1, limit: int = 30, user: dict = Depends(require_admin)):
    from admin_service import list_flagged_scans
    return list_flagged_scans(page=page, limit=limit)


@app.get("/api/v1/admin/review/llm-calls")
@limiter.limit("120/minute")
async def admin_review_llm_calls(request: Request, page: int = 1, limit: int = 50, scan_id: Optional[str] = None, user: dict = Depends(require_admin)):
    from admin_service import list_llm_calls
    return list_llm_calls(page=page, limit=limit, scan_id=scan_id or "")


@app.post("/api/v1/admin/review/scans/{scan_id}/review")
@limiter.limit("60/minute")
async def admin_mark_scan_reviewed(request: Request, scan_id: str, body: ReviewMarkBody, user: dict = Depends(require_admin)):
    from admin_service import mark_scan_reviewed
    from audit_log import log_from_request
    _require_json(request)
    out = mark_scan_reviewed(scan_id, user.get("user_id", ""), body.note or "")
    log_from_request(request, "admin.review.marked", admin_user=user, resource_type="scan", resource_id=scan_id, detail=f"note={ (body.note or '')[:200] }")
    return out


@app.get("/api/v1/admin/events")
@limiter.limit("60/minute")
async def admin_events_list(request: Request, user: dict = Depends(require_admin)):
    """Legacy alias — returns audit log entries."""
    from audit_log import list_audit_logs
    data = list_audit_logs(page=1, limit=60)
    events = [{
        "type": "audit",
        "title": e["action"],
        "detail": f"{e['user_email'] or 'system'} @ {e['ip_address'] or '—'} — {e['detail']}",
        "timestamp": e["timestamp"],
        "badge": "ADMIN" if e["is_admin"] else "USER",
    } for e in data["items"]]
    return {"events": events}


@app.get("/api/v1/admin/billing/records")
@limiter.limit("60/minute")
async def admin_billing_records(request: Request, user: dict = Depends(require_admin)):
    from database import get_db, User
    
    with get_db() as db:
        premium_users = db.query(User).filter(User.plan == "premium").order_by(User.premium_until.asc()).all()
        pending_users = db.query(User).filter(User.pending_payment_ref != "").order_by(User.updated_at.desc()).all()
        inactive_premium = db.query(User).filter(
            User.plan != "premium",
            (User.paystack_subscription_code != "") | (User.subscription_status.in_(["cancelled", "expired", "past_due"]))
        ).order_by(User.updated_at.desc()).all()
        
        def _codes(u):
            cc = (u.paystack_customer_code or "").strip()
            sc = (u.paystack_subscription_code or "").strip()
            source = "paystack" if cc or sc else "manual"
            return {
                "customer_code": cc or ("Not linked (manual grant)" if source == "manual" else "—"),
                "subscription_code": sc or ("Not linked (manual grant)" if source == "manual" else "—"),
                "billing_source": source,
            }

        active_list = []
        for u in premium_users:
            codes = _codes(u)
            active_list.append({
                "user_id": u.user_id,
                "email": u.email,
                "name": u.name,
                "status": u.subscription_status or "active",
                "premium_until": u.premium_until,
                "customer_code": codes["customer_code"],
                "subscription_code": codes["subscription_code"],
                "billing_source": codes["billing_source"],
            })
            
        pending_list = []
        for u in pending_users:
            pending_list.append({
                "user_id": u.user_id,
                "email": u.email,
                "name": u.name,
                "reference": u.pending_payment_ref,
                "plan_id": u.pending_plan_id or "premium_monthly",
                "initiated_at": u.updated_at
            })
            
        inactive_list = []
        for u in inactive_premium:
            codes = _codes(u)
            inactive_list.append({
                "user_id": u.user_id,
                "email": u.email,
                "name": u.name,
                "status": u.subscription_status or "inactive",
                "last_active": u.updated_at,
                "customer_code": codes["customer_code"],
                "subscription_code": codes["subscription_code"],
                "billing_source": codes["billing_source"],
            })
            
    return {
        "active_subscriptions": active_list,
        "pending_payments": pending_list,
        "inactive_subscriptions": inactive_list
    }


@app.post("/api/v1/admin/billing/verify-manual")
@limiter.limit("20/hour")
async def admin_billing_verify_manual(request: Request, body: AdminManualVerifyBody, user: dict = Depends(require_admin)):
    from database import get_db, User
    from billing_service import verify_payment
    from audit_log import log_from_request
    _require_json(request)
    
    email_l = body.user_email.strip().lower()
    with get_db() as db:
        u = db.query(User).filter(User.email == email_l).first()
        if not u:
            raise HTTPException(404, "User with this email not found")
        user_id = u.user_id
        
    out = verify_payment(body.reference, user_id)
    log_from_request(
        request, "admin.billing.verify_manual", admin_user=user,
        resource_type="payment", resource_id=body.reference,
        detail=f"email={email_l}",
    )
    return out


@app.post("/api/v1/admin/billing/sync-user/{user_id}")
@limiter.limit("30/hour")
async def admin_billing_sync_user(request: Request, user_id: str, user: dict = Depends(require_admin)):
    from billing_service import sync_user_paystack_codes
    from audit_log import log_from_request
    out = sync_user_paystack_codes(user_id)
    log_from_request(request, "admin.billing.sync_paystack", admin_user=user, resource_type="user", resource_id=user_id)
    return out


@app.get("/api/v1/admin/scans/{scan_id}/report")
@limiter.limit("120/minute")
async def admin_scan_report(request: Request, scan_id: str, user: dict = Depends(require_admin)):
    data = get_report(scan_id)
    if not data:
        raise HTTPException(404, "Report not found")
    return data


@app.post("/api/v1/public/scan/website")
@limiter.limit("8/hour")
async def public_scan_website(request: Request, body: UrlBody):
    _require_json(request)
    url = validate_url(body.url)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "website")
    return _stream_agent("website", url, scan_id, user_id="", scan_tier="guest")


@app.post("/api/v1/public/scan/email")
@limiter.limit("8/hour")
async def public_scan_email(request: Request, body: EmailBody):
    _require_json(request)
    email = validate_email(body.email)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "email")
    return _stream_agent("email", email, scan_id, user_id="", scan_tier="guest")


@app.post("/api/v1/public/scan/link")
@limiter.limit("8/hour")
async def public_scan_link(request: Request, body: UrlBody):
    _require_json(request)
    url = validate_url(body.url)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "website")
    return _stream_agent("website", url, scan_id, user_id="", scan_tier="guest")


@app.post("/api/v1/public/scan/api")
@limiter.limit("8/hour")
async def public_scan_api(request: Request, body: UrlBody):
    _require_json(request)
    url = validate_url(body.url)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "api")
    return _stream_agent("api", url, scan_id, user_id="", scan_tier="guest")


@app.post("/api/v1/billing/upgrade")
@limiter.limit("10/hour")
async def billing_upgrade(request: Request, user: dict = Depends(require_user)):
    """Dev fallback when Paystack keys are not set."""
    from billing_service import paystack_configured

    if paystack_configured():
        raise HTTPException(400, "Use Paystack checkout on the pricing page")
    return {"user": upgrade_user_premium(user["user_id"]), "message": "Upgraded to Premium (dev — no payment)"}


@app.get("/api/v1/billing/pricing")
@limiter.limit("120/minute")
async def billing_pricing(request: Request):
    from billing_service import paystack_configured, paystack_status
    from pricing import pricing_payload

    st = paystack_status()
    return {
        **pricing_payload(),
        "paystack_public_key": os.getenv("PAYSTACK_PUBLIC_KEY", "").strip() if st["ready"] else "",
        "paystack_enabled": paystack_configured(),
        "paystack_status": st,
    }


@app.post("/api/v1/billing/checkout")
@limiter.limit("20/hour")
async def billing_checkout(request: Request, body: CheckoutBody, user: dict = Depends(require_user)):
    from billing_service import initialize_checkout

    _require_json(request)
    page = (body.return_page or "dashboard.html").strip()
    if not page.endswith(".html"):
        page = page + ".html" if "." not in page else page
    if "/" in page or ".." in page:
        page = "dashboard.html"
    return initialize_checkout(user, body.plan_id, return_page=page)


@app.post("/api/v1/billing/retry-charges")
async def billing_retry_charges(request: Request):
    from cron_jobs import verify_cron_secret
    from billing_service import run_charge_retry_batch

    body = await request.body()
    sig = request.headers.get("x-cron-secret", "")
    if not verify_cron_secret(sig):
        raise HTTPException(401, "Invalid cron secret")
    # optional query param days
    import urllib.parse
    q = urllib.parse.parse_qs(request.url.query)
    days = int(q.get("days", ["7"])[0]) if q.get("days") else 7
    return run_charge_retry_batch(grace_days=days)


@app.get("/api/v1/billing/verify")
@limiter.limit("60/minute")
async def billing_verify(request: Request, reference: str, user: dict = Depends(require_user)):
    from billing_service import verify_payment

    if not reference:
        raise HTTPException(400, "reference required")
    return verify_payment(reference, user["user_id"])


@app.post("/api/v1/billing/webhook")
async def billing_webhook(request: Request):
    from billing_service import handle_webhook, verify_paystack_signature

    body = await request.body()
    sig = request.headers.get("x-paystack-signature", "")
    if not verify_paystack_signature(body, sig):
        raise HTTPException(401, "Invalid Paystack signature")
    import json

    payload = json.loads(body.decode("utf-8"))
    return handle_webhook(payload)


@app.post("/api/v1/billing/cancel")
@limiter.limit("10/hour")
async def billing_cancel(request: Request, user: dict = Depends(require_user)):
    from billing_service import cancel_subscription

    return cancel_subscription(user["user_id"])


@app.get("/api/v1/plans")
@limiter.limit("120/minute")
async def plans_info(request: Request):
    from plans import FREE_MODULES, PREMIUM_MODULES, PLAN_LIMITS, TRIAL_DAYS
    from pricing import pricing_payload

    return {
        "trial_days": TRIAL_DAYS,
        "free_modules": sorted(FREE_MODULES),
        "premium_modules": sorted(PREMIUM_MODULES),
        "plans": PLAN_LIMITS,
        "pricing": pricing_payload(),
    }


@app.post("/api/v1/scan/website")
@limiter.limit("10/hour")
async def scan_website(request: Request, body: UrlBody):
    _require_json(request)
    user = _guard(request, "website")
    url = validate_url(body.url)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "website")
    return _stream_agent("website", url, scan_id, user["user_id"], scan_tier=tier_for_user(user))


@app.post("/api/v1/scan/vulnerability")
@limiter.limit("10/hour")
async def scan_vulnerability(request: Request, body: UrlBody):
    _require_json(request)
    user = _guard(request, "vulnerability")
    url = validate_url(body.url)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "vulnerability")
    return _stream_agent("vulnerability", url, scan_id, user["user_id"], scan_tier=tier_for_user(user))


@app.post("/api/v1/scan/subdomains")
@limiter.limit("10/hour")
async def scan_subdomains(request: Request, body: DomainBody):
    _require_json(request)
    user = _guard(request, "subdomains")
    domain = validate_domain(body.domain)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "subdomains")
    return _stream_agent("subdomains", domain, scan_id, user["user_id"], scan_tier=tier_for_user(user))


@app.post("/api/v1/scan/ip")
@limiter.limit("10/hour")
async def scan_ip(request: Request, body: IpBody):
    _require_json(request)
    user = _guard(request, "ip")
    ip = validate_public_ip(body.ip)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "ip")
    return _stream_agent("ip", ip, scan_id, user["user_id"], scan_tier=tier_for_user(user))


@app.post("/api/v1/scan/organization")
@limiter.limit("10/hour")
async def scan_organization(request: Request, body: OrgBody):
    _require_json(request)
    user = _guard(request, "organization")
    name, domain = validate_org(body.name, body.domain)
    target = f"{name}|{domain}".strip("|")
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "organization")
    return _stream_agent("organization", target, scan_id, user["user_id"], scan_tier=tier_for_user(user))


@app.post("/api/v1/scan/person")
@limiter.limit("10/hour")
async def scan_person(request: Request, body: PersonBody):
    _require_json(request)
    user = _guard(request, "person")
    name, keywords = validate_person(body.name, body.keywords)
    target = f"{name}|{keywords}"
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "person")
    return _stream_agent("person", target, scan_id, user["user_id"], scan_tier=tier_for_user(user))


@app.post("/api/v1/scan/company")
@limiter.limit("10/hour")
async def scan_company(request: Request, body: OrgBody):
    _require_json(request)
    user = _guard(request, "company")
    name, domain = validate_company(body.name, body.domain)
    target = f"{name}|{domain}".strip("|") or domain
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "company")
    return _stream_agent("company", target or name, scan_id, user["user_id"], scan_tier=tier_for_user(user))


@app.post("/api/v1/scan/email")
@limiter.limit("10/hour")
async def scan_email(request: Request, body: EmailBody):
    _require_json(request)
    user = _guard(request, "email")
    email = validate_email(body.email)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "email")
    return _stream_agent("email", email, scan_id, user["user_id"], scan_tier=tier_for_user(user))


@app.post("/api/v1/scan/domain")
@limiter.limit("10/hour")
async def scan_domain(request: Request, body: DomainBody):
    _require_json(request)
    user = _guard(request, "domain")
    domain = validate_domain(body.domain)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "domain")
    return _stream_agent("domain", domain, scan_id, user["user_id"], scan_tier=tier_for_user(user))


@app.post("/api/v1/scan/link")
@limiter.limit("10/hour")
async def scan_link(request: Request, body: UrlBody):
    _require_json(request)
    user = _guard(request, "website")
    url = validate_url(body.url)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "website")
    return _stream_agent("website", url, scan_id, user["user_id"], scan_tier=tier_for_user(user))


@app.post("/api/v1/scan/api")
@limiter.limit("10/hour")
async def scan_api(request: Request, body: UrlBody):
    _require_json(request)
    user = _guard(request, "api")
    url = validate_url(body.url)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "api")
    return _stream_agent("api", url, scan_id, user["user_id"], scan_tier=tier_for_user(user))


# Sandbox routes
SANDBOX_MODULES = ["website", "vulnerability", "subdomains", "ip", "organization", "person", "company", "email", "domain", "api", "link"]


def _make_sandbox_route(module: str):
    async def sandbox_scan(request: Request, scenario: str = "clean_scan"):
        # Sandbox serves mock data only — auth is optional.
        # enforce_scan_access already handles user=None safely.
        user = get_current_user_from_request(request)
        enforce_scan_access(user, module, sandbox=True)
        async def gen():
            async for line in stream_sandbox(module, scenario):
                yield line
        return StreamingResponse(gen(), media_type="text/plain")
    return sandbox_scan


for _mod in SANDBOX_MODULES:
    app.add_api_route(f"/api/v1/sandbox/scan/{_mod}", _make_sandbox_route(_mod), methods=["POST"])


@app.get("/api/v1/sandbox/report/{module}")
async def sandbox_report(module: str, scenario: str = "clean_scan"):
    return get_mock_report(module, scenario)


@app.get("/api/v1/public/report/{share_token}")
@limiter.limit("120/minute")
async def public_report(request: Request, share_token: str):
    """View a shared report without signing in."""
    data = get_report_by_share_token(share_token)
    if not data:
        raise HTTPException(404, "Shared report not found or link expired")
    return data


@app.post("/api/v1/report/{scan_id}/share")
@limiter.limit("60/minute")
async def report_share(request: Request, scan_id: str, user: dict = Depends(require_user)):
    token = enable_report_share(scan_id, user["user_id"])
    if not token:
        raise HTTPException(404, "Report not found")
    return {"scan_id": scan_id, "share_token": token}


@app.get("/api/v1/report/{scan_id}")
@limiter.limit("120/minute")
async def report(request: Request, scan_id: str):
    """Return a saved report. If the report has an owning `user_id`, require that
    the requester is authenticated and matches the owner. If the report has no
    owner (guest/public scan), allow anonymous access.
    """
    data = get_report(scan_id)
    if not data:
        raise HTTPException(404, "Report not found")
    owner = (data.get("user_id") or "").strip()
    if not owner:
        return data
    # Report has an owner — require authenticated user and matching id
    from auth_service import get_current_user_from_request
    user = get_current_user_from_request(request)
    if not user or user.get("user_id") != owner:
        raise HTTPException(401, "Sign in required")
    return data


@app.get("/api/v1/history")
@limiter.limit("60/minute")
async def history(
    request: Request,
    type: Optional[str] = None,
    q: Optional[str] = None,
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(require_user),
):
    limit = min(max(limit, 1), 50)
    page = max(page, 1)
    items, total = list_history(
        limit=limit,
        offset=(page - 1) * limit,
        scan_type=type,
        query=q,
        user_id=user["user_id"],
    )
    return {"items": items, "total": total, "page": page, "limit": limit}


@app.delete("/api/v1/report/{scan_id}")
@limiter.limit("30/minute")
async def remove_report(request: Request, scan_id: str, user: dict = Depends(require_user)):
    if not delete_scan(scan_id, user_id=user["user_id"]):
        raise HTTPException(404, "Not found")
    return {"deleted": True}


@app.delete("/api/v1/history")
@limiter.limit("10/hour")
async def clear_history(request: Request, user: dict = Depends(require_user)):
    return {"deleted": delete_all_scans(user_id=user["user_id"])}


@app.post("/api/v1/keys/generate")
@limiter.limit("20/hour")
async def keys_generate(request: Request, body: KeyGenBody, user: dict = Depends(require_user)):
    _require_json(request)
    try:
        return generate_api_key(user["user_id"], user, sandbox=body.sandbox, name=body.name)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/v1/keys/list")
@limiter.limit("60/minute")
async def keys_list(request: Request, user: dict = Depends(require_user)):
    return {"keys": list_keys_for_user(user["user_id"]), "account": usage_payload(user)}


@app.delete("/api/v1/keys/{key_id}")
@limiter.limit("30/minute")
async def keys_revoke(request: Request, key_id: str, user: dict = Depends(require_user)):
    if not revoke_key(key_id, user["user_id"]):
        raise HTTPException(404, "Key not found")
    return {"revoked": True}


@app.get("/api/v1/keys/usage")
@limiter.limit("60/minute")
async def keys_usage(request: Request, user: dict = Depends(require_user)):
    """Account + optional current API key usage from request headers."""
    account = usage_payload(user)
    api_key = request.headers.get("X-API-Key") or request.headers.get("x-api-key")
    key_info = lookup_api_key(api_key, increment_usage=False) if api_key else None
    current_key = None
    if key_info and key_info.get("user_id") == user["user_id"]:
        keys = list_keys_for_user(user["user_id"])
        current_key = next((k for k in keys if k["key_id"] == key_info["key_id"]), None)
    return {"account": account, "current_key": current_key}


@app.post("/api/v1/contact")
@limiter.limit("10/hour")
async def contact(request: Request, body: ContactBody):
    _require_json(request)
    save_contact(body.name, body.email, body.subject, body.message)
    return {"status": "received"}


@app.get("/api/v1/monitors")
@limiter.limit("60/minute")
async def monitors_list(request: Request):
    return {"monitors": list_monitors()}


@app.post("/api/v1/monitors")
@limiter.limit("30/hour")
async def monitors_add(request: Request, body: MonitorBody):
    _require_json(request)
    user = get_current_user_from_request(request)
    if user:
        from usage_guard import enforce_scan_access
        enforce_scan_access(user, "monitor", sandbox=False)
    alert_email = (body.alert_email or "").strip()
    if not alert_email and user:
        alert_email = user.get("email", "")
    mid = str(uuid.uuid4())
    save_monitor(mid, body.target, body.target_type, body.frequency, alert_email)
    if user:
        from audit_log import log_from_request
        log_from_request(request, "monitor.add", user=user, resource_type="monitor", resource_id=mid, detail=body.target[:120])
    return {"monitor_id": mid}


@app.post("/api/v1/monitor/add")
@limiter.limit("30/hour")
async def monitor_add_alias(request: Request, body: MonitorBody):
    return await monitors_add(request, body)


@app.get("/api/v1/monitor/list")
@limiter.limit("60/minute")
async def monitor_list_alias(request: Request):
    return await monitors_list(request)


@app.delete("/api/v1/monitor/{monitor_id}")
@limiter.limit("30/hour")
async def monitor_delete(request: Request, monitor_id: str):
    if not delete_monitor(monitor_id):
        raise HTTPException(404, "Monitor not found")
    return {"deleted": True}


@app.get("/api/v1/monitor/alerts")
@limiter.limit("60/minute")
async def monitor_alerts(request: Request):
    return {"alerts": list_monitor_alerts()}


@app.post("/api/v1/verify/domain")
@limiter.limit("20/hour")
async def verify_domain_start(request: Request, body: VerifyDomainBody):
    _require_json(request)
    domain = validate_domain(body.domain)
    token = generate_token()
    create_domain_verification(domain, token)
    return {"domain": domain, "txt_record": token, "instructions": f"Add TXT record: {token}"}


@app.get("/api/v1/verify/domain/{domain}")
@limiter.limit("60/minute")
async def verify_domain_status(request: Request, domain: str):
    domain = validate_domain(domain)
    info = get_domain_verification(domain)
    if not info:
        raise HTTPException(404, "Verification not started")
    if not info["verified"] and check_txt_record(domain, info["verify_token"]):
        mark_domain_verified(domain)
        info["verified"] = True
    return info


@app.post("/api/v1/verify/domain/{domain}/check")
@limiter.limit("20/hour")
async def verify_domain_check(request: Request, domain: str):
    return await verify_domain_status(request, domain)


@app.get("/api/v1/history/scores/{domain}")
@limiter.limit("60/minute")
async def history_scores(request: Request, domain: str):
    domain = validate_domain(domain)
    return {"domain": domain, "scores": get_score_history(domain)}


@app.patch("/api/v1/findings/{finding_id}")
@limiter.limit("60/minute")
async def patch_finding(request: Request, finding_id: str, body: FindingPatchBody):
    _require_json(request)
    existing = get_finding_status(finding_id)
    upsert_finding_status(
        finding_id,
        body.scan_id or (existing.get("scan_id", "") if existing else ""),
        body.domain or "",
        body.finding_title or (existing.get("finding_title", "Finding") if existing else "Finding"),
        body.severity,
        body.status,
        body.note,
    )
    return {"finding_id": finding_id, "status": body.status}


@app.get("/api/v1/remediation/{domain}")
@limiter.limit("60/minute")
async def remediation_stats(request: Request, domain: str):
    domain = validate_domain(domain)
    return remediation_progress(domain)


@app.post("/api/v1/scan/template")
@limiter.limit("5/hour")
async def scan_template(request: Request, body: TemplateScanBody):
    _require_json(request)
    user = _guard(request, "templates")
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "template")

    async def gen():
        for chunk in run_template(body.template, body.target, scan_id, user_id=user["user_id"]):
            yield chunk

    return StreamingResponse(gen(), media_type="text/plain")


@app.post("/api/v1/scan/auth")
@limiter.limit("10/hour")
async def scan_auth(request: Request, body: AuthScanBody):
    _require_json(request)
    user = _guard(request, "auth")
    if not body.authorized:
        raise HTTPException(400, "Authorization confirmation required")
    url = validate_url(body.url)
    scan_id = str(uuid.uuid4())
    log_scan(scan_id, "auth")

    async def gen():
        yield f"[AKILI] Starting authenticated scan...\n"
        result = run_auth_scan(url, body.auth_type, dict(body.credentials), body.depth)
        from database import save_scan

        report = {
            "scan_type": "auth",
            "target": url,
            "success": result.get("success"),
            "findings": result.get("findings", []),
            "summary": result.get("summary", result.get("error", "")),
            "grade": result.get("grade", "C"),
            "score": result.get("score", 50),
        }
        save_scan(scan_id, "auth", url, report, 1, user_id=user["user_id"])
        yield f"[DONE] Authenticated scan complete\n"
        yield f"COMPLETE:{__import__('json').dumps(report)}\n"

    return StreamingResponse(gen(), media_type="text/plain")


@app.post("/api/v1/scan/api")
@limiter.limit("20/hour")
async def scan_api_endpoint(request: Request, body: ApiScanBody):
    _require_json(request)
    user = _guard(request, "vuln")
    url = validate_url(body.url)
    try:
        # Run the enhanced API scanner with provided options
        result = scan_api(
            url,
            methods=body.methods,
            headers=body.headers,
            form_payload=body.form_payload,
            auth=body.auth,
            timeout=int(body.timeout or 8),
            diff=bool(body.diff),
        )
        return result
    except Exception as e:
        raise HTTPException(500, f"API scan failed: {str(e)}")


@app.post("/api/v1/agency/profile")
@limiter.limit("20/hour")
async def agency_create(request: Request, body: AgencyProfileBody):
    _require_json(request)
    key_info = lookup_api_key(request.headers.get("X-API-Key"), increment_usage=False)
    api_key_id = key_info["key_id"] if key_info else "browser"
    if key_info and key_info.get("tier") == "free":
        return JSONResponse({"detail": "White label reports require Pro tier or above"}, status_code=403)
    pid = str(uuid.uuid4())
    save_agency_profile(pid, api_key_id, body.model_dump())
    return {"profile_id": pid}


@app.get("/api/v1/agency/profile")
@limiter.limit("60/minute")
async def agency_get(request: Request):
    key_info = lookup_api_key(request.headers.get("X-API-Key"), increment_usage=False)
    if not key_info:
        raise HTTPException(404, "No API key")
    profile = get_agency_profile(key_info["key_id"])
    if not profile:
        raise HTTPException(404, "No agency profile")
    return profile


@app.put("/api/v1/agency/profile")
@limiter.limit("20/hour")
async def agency_update(request: Request, body: AgencyProfileBody):
    return await agency_create(request, body)


# Legacy aliases for frontend without /v1
@app.get("/api/health")
async def health_legacy(request: Request):
    return await health(request)


@app.get("/api/history")
async def history_legacy(request: Request, type: Optional[str] = None, q: Optional[str] = None, page: int = 1, limit: int = 20):
    return await history(request, type, q, page, limit)


@app.get("/api/public/report/{share_token}")
async def public_report_legacy(request: Request, share_token: str):
    return await public_report(request, share_token)


@app.get("/api/report/{scan_id}")
async def report_legacy(request: Request, scan_id: str, user: dict = Depends(require_user)):
    return await report(request, scan_id, user)




