"""User auth — email/password, Google OAuth, JWT sessions."""

import hashlib
import os
import re
import secrets
import time
import uuid
from typing import Any, Optional

import bcrypt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
import logging

from database import ApiKey, Scan, UsageCounter, User, get_db, update_user_profile
from plans import TRIAL_DAYS, effective_plan, get_limits

load_dotenv()

logger = logging.getLogger("akili.auth")

JWT_SECRET = os.getenv("JWT_SECRET", "akili-dev-secret-change-in-production")
JWT_ALG = "HS256"
JWT_EXPIRE_DAYS = 30
GOOGLE_CLIENT_ID = (os.getenv("GOOGLE_CLIENT_ID", "") or "").strip()
ADMIN_PIN = (os.getenv("ADMIN_PIN", "") or "").strip()
RESET_TOKEN_HOURS = 1
EMAIL_VERIFY_HOURS = 48

bearer = HTTPBearer(auto_error=False)


def _email_ok(email: str) -> bool:
    return bool(re.match(r"^[\w.\-]+@[\w.\-]+\.\w+$", email.strip(), re.I))


def _password_digest(password: str) -> str:
    """Bcrypt accepts max 72 bytes — use SHA-256 hex digest first."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    digest = _password_digest(password).encode("utf-8")
    return bcrypt.hashpw(digest, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    if not hashed:
        return False
    digest = _password_digest(password).encode("utf-8")
    try:
        if bcrypt.checkpw(digest, hashed.encode("utf-8")):
            return True
    except Exception:
        pass
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(user_id: str) -> str:
    now = int(time.time())
    exp = now + JWT_EXPIRE_DAYS * 86400
    payload = {"sub": user_id, "iat": now, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> Optional[str]:
    if not token:
        return None
    try:
        # Some jose.jwt versions do not accept a `leeway` kwarg. Decode without
        # verifying expiration, then check `exp` manually with a small leeway.
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG], options={"verify_aud": False, "verify_exp": False})
        exp = payload.get("exp")
        now = int(time.time())
        if exp is not None:
            try:
                exp_i = int(exp)
            except Exception:
                exp_i = 0
            # allow 120s clock skew
            if now > exp_i + 120:
                preview = (token or "")[:64]
                logger.info("JWT expired (exp=%s now=%s) token_preview=%s", exp_i, now, preview)
                return None
        return payload.get("sub")
    except JWTError as e:
        try:
            preview = (token or "")[:64]
        except Exception:
            preview = "<token-preview-failed>"
        logger.warning("JWT decode failed: %s; token_preview=%s", str(e), preview)
        return None


def user_to_dict(row: User) -> dict:
    role = getattr(row, "role", None) or "user"
    return {
        "user_id": row.user_id,
        "email": row.email,
        "name": row.name or "",
        "phone": getattr(row, "phone", None) or "",
        "organization": getattr(row, "organization", None) or "",
        "job_title": getattr(row, "job_title", None) or "",
        "country": getattr(row, "country", None) or "",
        "plan": row.plan,
        "trial_ends_at": row.trial_ends_at,
        "created_at": row.created_at,
        "updated_at": getattr(row, "updated_at", None) or 0,
        "google_id": bool(row.google_id),
        "role": role,
        "is_admin": role == "admin",
        "effective_plan": effective_plan(_user_plan_ctx(row)),
        "subscription_status": getattr(row, "subscription_status", None) or "",
        "premium_until": getattr(row, "premium_until", None) or 0,
        "email_verified": bool(getattr(row, "email_verified", False) or row.google_id),
    }


def _user_plan_ctx(row: User) -> dict:
    return {
        "plan": row.plan,
        "trial_ends_at": row.trial_ends_at,
        "subscription_status": getattr(row, "subscription_status", None) or "",
        "premium_until": getattr(row, "premium_until", None) or 0,
    }


def register_user(
    email: str,
    password: str,
    name: str = "",
    confirm_password: str = "",
    phone: str = "",
) -> dict:
    if not _email_ok(email):
        raise HTTPException(400, "Invalid email address")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if confirm_password and password != confirm_password:
        raise HTTPException(400, "Passwords do not match")
    email_l = email.strip().lower()
    now = int(time.time())
    user_id = str(uuid.uuid4())
    trial_end = now + TRIAL_DAYS * 86400

    with get_db() as db:
        if db.query(User).filter(User.email == email_l).first():
            raise HTTPException(409, "Email already registered")
        verify_token = secrets.token_urlsafe(32)
        row = User(
            user_id=user_id,
            email=email_l,
            password_hash=hash_password(password),
            name=(name or email_l.split("@")[0])[:120],
            phone=(phone or "")[:40],
                plan="trial",
            trial_ends_at=trial_end,
            google_id="",
            created_at=now,
            updated_at=now,
            is_active=True,
            email_verified=False,
            email_verify_hash=_hash_reset_token(verify_token),
        )
        db.add(row)
        user_out = user_to_dict(row)

    token = create_token(user_id)
    try:
        from email_service import send_welcome, send_email_verification
        send_welcome(email_l, user_out.get("name", ""))
        send_email_verification(email_l, user_out.get("name", ""), verify_token)
    except Exception:
        pass
    return {"token": token, "user": user_out, "verify_email_sent": True}


def login_user(email: str, password: str) -> dict:
    email_l = email.strip().lower()
    with get_db() as db:
        row = db.query(User).filter(User.email == email_l).first()
        if not row:
            raise HTTPException(401, "Invalid email or password")
        if not row.is_active:
            raise HTTPException(403, "This account is deactivated. Please contact an administrator.")
        if not row.password_hash:
            raise HTTPException(401, "Invalid email or password")
        if not verify_password(password, row.password_hash):
            raise HTTPException(401, "Invalid email or password")
        user_out = user_to_dict(row)
        token = create_token(row.user_id)
    return {"token": token, "user": user_out}


def google_login(id_token: str) -> dict:
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(503, "Google sign-in is not configured (set GOOGLE_CLIENT_ID)")
    try:
        from google.oauth2 import id_token as google_id_token
        from google.auth.transport import requests as google_requests

        info = google_id_token.verify_oauth2_token(
            id_token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except Exception:
        raise HTTPException(401, "Invalid Google token")

    email = (info.get("email") or "").lower()
    if not email:
        raise HTTPException(400, "Google account has no email")
    google_sub = info.get("sub", "")
    name = info.get("name", "")[:120]
    now = int(time.time())

    is_new = False
    with get_db() as db:
        row = db.query(User).filter(
            (User.google_id == google_sub) | (User.email == email)
        ).first()
        if not row:
            is_new = True
            user_id = str(uuid.uuid4())
            row = User(
                user_id=user_id,
                email=email,
                password_hash="",
                name=name,
                plan="trial",
                trial_ends_at=now + TRIAL_DAYS * 86400,
                google_id=google_sub,
                created_at=now,
                is_active=True,
                email_verified=True,
            )
            db.add(row)
        else:
            if not row.is_active:
                raise HTTPException(403, "This account is deactivated. Please contact an administrator.")
            if not row.google_id:
                row.google_id = google_sub
            if name and not row.name:
                row.name = name
        user_out = user_to_dict(row)
        token = create_token(row.user_id)
    if is_new:
        try:
            from email_service import send_welcome
            send_welcome(email, user_out.get("name", ""))
        except Exception:
            pass
    return {"token": token, "user": user_out}


def get_user_by_id(user_id: str) -> Optional[dict]:
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id, User.is_active == True).first()
        if not row:
            return None
        from billing_service import reconcile_user_plan

        reconcile_user_plan(row)
        try:
            maybe_send_renewal_reminder(row)
        except Exception:
            pass
        return user_to_dict(row)


def maybe_send_renewal_reminder(row: User) -> None:
    """Email once when Premium renews within 7 days."""
    if row.plan != "premium":
        return
    until = int(getattr(row, "premium_until", None) or 0)
    if until <= 0:
        return
    now = int(time.time())
    days_left = (until - now) // 86400
    if days_left < 0 or days_left > 7:
        return
    last = int(getattr(row, "renewal_reminder_at", None) or 0)
    if last and (now - last) < 5 * 86400:
        return
    from datetime import datetime
    from email_service import send_renewal_reminder

    renew_date = datetime.utcfromtimestamp(until).strftime("%d %b %Y")
    send_renewal_reminder(row.email, row.name or "", max(1, days_left), renew_date)
    with get_db() as db:
        u = db.query(User).filter(User.user_id == row.user_id).first()
        if u:
            u.renewal_reminder_at = now


def request_password_reset(email: str) -> dict:
    """Always return success to avoid email enumeration."""
    email_l = email.strip().lower()
    if not _email_ok(email_l):
        return {"message": "If that email exists, we sent a reset link."}
    token = secrets.token_urlsafe(32)
    token_hash = _hash_reset_token(token)
    expires = int(time.time()) + RESET_TOKEN_HOURS * 3600
    with get_db() as db:
        row = db.query(User).filter(User.email == email_l, User.is_active == True).first()
        if row and row.password_hash:
            row.password_reset_hash = token_hash
            row.password_reset_expires = expires
            try:
                from email_service import send_password_reset
                send_password_reset(row.email, row.name or "", token)
            except Exception:
                pass
    return {"message": "If that email exists, we sent a reset link."}


def reset_password_with_token(token: str, new_password: str) -> dict:
    if len(new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    token = (token or "").strip()
    if len(token) < 20:
        raise HTTPException(400, "Invalid or expired reset link")
    token_hash = _hash_reset_token(token)
    now = int(time.time())
    with get_db() as db:
        row = (
            db.query(User)
            .filter(
                User.password_reset_hash == token_hash,
                User.password_reset_expires >= now,
                User.is_active == True,
            )
            .first()
        )
        if not row:
            raise HTTPException(400, "Invalid or expired reset link")
        row.password_hash = hash_password(new_password)
        row.password_reset_hash = ""
        row.password_reset_expires = 0
        row.updated_at = now
        user_out = user_to_dict(row)
        jwt_token = create_token(row.user_id)
    return {"token": jwt_token, "user": user_out, "message": "Password updated"}


def verify_email_token(token: str) -> dict:
    token = (token or "").strip()
    if len(token) < 20:
        raise HTTPException(400, "Invalid verification link")
    token_hash = _hash_reset_token(token)
    with get_db() as db:
        row = db.query(User).filter(User.email_verify_hash == token_hash, User.is_active == True).first()
        if not row:
            raise HTTPException(400, "Invalid or expired verification link")
        row.email_verified = True
        row.email_verify_hash = ""
        row.updated_at = int(time.time())
        user_out = user_to_dict(row)
    return {"verified": True, "user": user_out}


def patch_user_profile(user_id: str, **fields) -> dict:
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id, User.is_active == True).first()
        if not row:
            raise HTTPException(404, "User not found")
        allowed = {"name", "phone", "organization", "job_title", "country"}
        for key, val in fields.items():
            if key in allowed:
                setattr(row, key, str(val or "")[:200] if key != "name" else str(val or "")[:120])
        row.updated_at = int(time.time())
        return user_to_dict(row)


def upgrade_user_premium(user_id: str) -> dict:
    from billing_service import _activate_premium

    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id).first()
        if not row:
            raise HTTPException(404, "User not found")
        _activate_premium(row)
    return get_user_by_id(user_id)


def delete_user_account(user_id: str, password: str = "") -> None:
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id, User.is_active == True).first()
        if not row:
            raise HTTPException(404, "Account not found")
        if row.password_hash:
            if not password:
                raise HTTPException(400, "Password required to delete account")
            if not verify_password(password, row.password_hash):
                raise HTTPException(401, "Incorrect password")

        try:
            from billing_service import cancel_subscription

            cancel_subscription(user_id)
        except HTTPException:
            pass

        db.query(ApiKey).filter(ApiKey.user_id == user_id).update({ApiKey.is_active: False})
        db.query(Scan).filter(Scan.user_id == user_id).delete()
        db.query(UsageCounter).filter(UsageCounter.user_id == user_id).delete()

        row.is_active = False
        row.email = f"deleted_{user_id[:12]}@removed.akili.local"
        row.password_hash = ""
        row.name = "Deleted user"
        row.google_id = ""
        row.plan = "expired"
        row.subscription_status = "cancelled"
        row.paystack_authorization = ""
        row.paystack_customer_code = ""
        row.paystack_subscription_code = ""
        row.pending_payment_ref = ""
        row.updated_at = int(time.time())


def _extract_token(request: Request, creds: Optional[HTTPAuthorizationCredentials] = None) -> Optional[str]:
    if creds and getattr(creds, "credentials", None):
        return creds.credentials
    token = request.headers.get("X-Session-Token") or request.cookies.get("akili_token")
    if token:
        return token
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def get_current_user_from_request(request: Request) -> Optional[dict]:
    token = _extract_token(request)
    if not token:
        logger.debug("No session token found in request from %s", request.client.host if getattr(request, 'client', None) else 'unknown')
        return None
    uid = decode_token(token)
    if not uid:
        logger.info("Invalid or expired token supplied from %s", request.client.host if getattr(request, 'client', None) else 'unknown')
        return None
    return get_user_by_id(uid)


def get_current_user(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
) -> Optional[dict]:
    token = _extract_token(request, creds)
    if not token:
        return None
    uid = decode_token(token)
    if not uid:
        return None
    return get_user_by_id(uid)


def require_user(request: Request, user: Optional[dict] = Depends(get_current_user)) -> dict:
    """Require a signed-in user. If an `X-API-Key` header is present, ensure the key is valid and
    belongs to the same user; reject invalid or mismatched keys.
    """
    if not user:
        raise HTTPException(401, "Sign in required")
    api_key = request.headers.get("X-API-Key") or request.headers.get("x-api-key")
    if api_key:
        try:
            from api_keys import lookup_api_key
        except Exception:
            lookup_api_key = None
        if lookup_api_key:
            key_info = lookup_api_key(api_key, increment_usage=False)
            if not key_info:
                try:
                    from audit_log import log_from_request
                    masked = (api_key[:6] + "…" + api_key[-6:]) if len(api_key) > 12 else api_key
                    log_from_request(request, "auth.api_key.invalid", user=user, detail=f"invalid_api_key={masked}")
                except Exception:
                    pass
                raise HTTPException(403, "Invalid API key")
            if key_info.get("user_id") and key_info.get("user_id") != user.get("user_id"):
                try:
                    from audit_log import log_from_request
                    masked = (api_key[:6] + "…" + api_key[-6:]) if len(api_key) > 12 else api_key
                    log_from_request(request, "auth.api_key.mismatch", user=user, detail=f"user_id={user.get('user_id')} key_id={key_info.get('key_id')} key_preview={masked}")
                except Exception:
                    pass
                raise HTTPException(403, "API key does not match authenticated user")
    return user


def require_admin(user: dict = Depends(require_user)) -> dict:
    if not user.get("is_admin"):
        raise HTTPException(403, "Admin access required")
    return user


def admin_login(email: str, password: str, admin_pin: str = "") -> dict:
    import hmac

    from admin_service import bootstrap_admin_user, is_admin_user

    if ADMIN_PIN and not hmac.compare_digest(ADMIN_PIN, (admin_pin or "").strip()):
        raise HTTPException(401, "Invalid admin security PIN")

    bootstrap_admin_user()
    email_l = email.strip().lower()
    with get_db() as db:
        row = db.query(User).filter(User.email == email_l, User.is_active == True).first()
        if not row or not row.password_hash:
            raise HTTPException(401, "Invalid email or password")
        if not verify_password(password, row.password_hash):
            raise HTTPException(401, "Invalid email or password")
        if not is_admin_user(row):
            raise HTTPException(403, "This account is not an administrator")
        return {"token": create_token(row.user_id), "user": user_to_dict(row)}
