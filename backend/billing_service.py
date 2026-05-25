"""Paystack billing — initialize payment, verify, webhooks, subscription state."""

import hashlib
import hmac
import logging
import os
import time
import uuid
from typing import Any, Optional

import requests
from dotenv import load_dotenv
from fastapi import HTTPException

from database import User, get_db
from pricing import PLANS

load_dotenv()

logger = logging.getLogger("akili.billing")

PAYSTACK_SECRET = (os.getenv("PAYSTACK_SECRET_KEY", "") or "").strip()
PAYSTACK_PUBLIC = (os.getenv("PAYSTACK_PUBLIC_KEY", "") or "").strip()
PAYSTACK_PREMIUM_PLAN = (os.getenv("PAYSTACK_PREMIUM_PLAN_CODE", "") or "").strip()
FRONTEND_URL = (os.getenv("FRONTEND_URL", "http://localhost:5501") or "").rstrip("/")
PAYSTACK_BASE = "https://api.paystack.co"


def _is_placeholder_key(key: str) -> bool:
    k = (key or "").strip().lower()
    if not k or len(k) < 12:
        return True
    if "xxxx" in k or "xxx" == k[-3:] or "your_" in k or "pk_test_" == k and k.count("_") < 2:
        return True
    if k in ("pk_test_xxxx", "sk_test_xxxx", "pln_xxxx"):
        return True
    return False


def paystack_configured() -> bool:
    # Payments are disabled; always report not configured
    return False


def paystack_status() -> dict:
    secret_ok = bool(PAYSTACK_SECRET) and not _is_placeholder_key(PAYSTACK_SECRET)
    public_ok = bool(PAYSTACK_PUBLIC) and not _is_placeholder_key(PAYSTACK_PUBLIC)
    plan_ok = bool(PAYSTACK_PREMIUM_PLAN) and not _is_placeholder_key(PAYSTACK_PREMIUM_PLAN)
    return {
        "ready": paystack_configured(),
        "secret_key_set": secret_ok,
        "public_key_set": public_ok,
        "plan_code_set": plan_ok,
        "message": (
            "Paystack is ready."
            if paystack_configured()
            else "Add real Paystack test/live keys to backend/.env (replace pk_test_xxxx placeholders)."
        ),
    }


def _paystack(method: str, path: str, payload: Optional[dict] = None) -> dict:
    # Payments disabled
    raise HTTPException(410, "Payments have been disabled on this deployment")
    url = f"{PAYSTACK_BASE}{path}"
    resp = requests.request(
        method,
        url,
        json=payload,
        headers={"Authorization": f"Bearer {PAYSTACK_SECRET}", "Content-Type": "application/json"},
        timeout=30,
    )
    try:
        data = resp.json()
    except Exception:
        raise HTTPException(502, "Invalid Paystack response")
    if not resp.ok or not data.get("status"):
        msg = data.get("message", "Paystack request failed")
        raise HTTPException(502, msg)
    return data.get("data") or {}


def reconcile_user_plan(row: User) -> None:
    """Downgrade premium if subscription lapsed or payment failed."""
    now = int(time.time())
    status = (getattr(row, "subscription_status", None) or "").strip()
    until = int(getattr(row, "premium_until", None) or 0)
    if row.plan != "premium":
        return
    if status in ("active", "non-renewing") and until > now:
        return
        fallback = (getattr(row, "plan_before_premium", None) or "trial").strip() or "trial"
        if fallback not in ("trial",):
            fallback = "trial"
    if (row.trial_ends_at or 0) > now:
        fallback = "trial"
    row.plan = fallback
    row.subscription_status = "expired"
    row.updated_at = now


def subscription_info(row: User) -> dict:
    reconcile_user_plan(row)
    return {
        "subscription_status": getattr(row, "subscription_status", None) or "",
        "premium_until": getattr(row, "premium_until", None) or 0,
        "paystack_configured": paystack_configured(),
    }


def initialize_checkout(user: dict, plan_id: str = "premium_monthly", return_page: str = "dashboard.html") -> dict:
    raise HTTPException(410, "Payments have been disabled on this deployment")


def _activate_premium(row: User, *, authorization_code: str = "", customer_code: str = "", subscription_code: str = "") -> None:
    now = int(time.time())
    if row.plan != "premium":
           row.plan_before_premium = row.plan if row.plan in ("trial",) else "trial"
    row.plan = "premium"
    row.subscription_status = "active"
    row.premium_until = now + 32 * 86400  # grace window until webhook renews
    row.updated_at = now
    if authorization_code:
        row.paystack_authorization = authorization_code[:120]
    if customer_code:
        row.paystack_customer_code = customer_code[:80]
    if subscription_code:
        row.paystack_subscription_code = subscription_code[:80]
    row.pending_payment_ref = ""
    row.pending_plan_id = ""


def _create_paystack_subscription(row: User, authorization_code: str, customer_email: str) -> None:
    if not PAYSTACK_PREMIUM_PLAN or not authorization_code:
        return
    customer_code = (row.paystack_customer_code or "").strip()
    if not customer_code:
        cust = _paystack(
            "POST",
            "/customer",
            {"email": customer_email, "first_name": (row.name or "AKILI")[:60]},
        )
        customer_code = cust.get("customer_code", "")
        row.paystack_customer_code = customer_code

    sub = _paystack(
        "POST",
        "/subscription",
        {
            "customer": customer_code,
            "plan": PAYSTACK_PREMIUM_PLAN,
            "authorization": authorization_code,
        },
    )
    row.paystack_subscription_code = (sub.get("subscription_code") or "")[:80]
    next_pay = sub.get("next_payment_date")
    if next_pay:
        try:
            from datetime import datetime

            dt = datetime.fromisoformat(str(next_pay).replace("Z", "+00:00"))
            row.premium_until = int(dt.timestamp())
        except Exception:
            pass


def verify_payment(reference: str, user_id: str) -> dict:
    if not paystack_configured():
        raise HTTPException(503, "Paystack not configured")
    data = _paystack("GET", f"/transaction/verify/{reference}")
    if data.get("status") != "success":
        raise HTTPException(400, "Payment not completed")

    currency = (data.get("currency") or "").upper()
    if currency and currency != "NGN":
        raise HTTPException(400, "Invalid payment currency")

    meta = data.get("metadata") or {}
    meta_uid = str(meta.get("user_id", "")) if isinstance(meta, dict) else ""
    plan_id = str(meta.get("plan_id", "") or "") if isinstance(meta, dict) else ""
    with get_db() as db:
        row_check = db.query(User).filter(User.user_id == user_id).first()
        pending = (row_check.pending_payment_ref or "") if row_check else ""
        pending_plan = (row_check.pending_plan_id or "") if row_check else ""
    if not plan_id:
        plan_id = pending_plan or "premium_monthly"
    plan = PLANS.get(plan_id)
    if not plan or not plan.get("price_kobo"):
        raise HTTPException(400, "Invalid plan in payment")
    paid_amount = int(data.get("amount") or 0)
    expected = int(plan["price_kobo"])
    if paid_amount != expected:
        logger.warning(
            "payment_amount_mismatch ref=%s paid=%s expected=%s user=%s",
            reference, paid_amount, expected, user_id,
        )
        raise HTTPException(400, "Payment amount does not match plan price")

    if meta_uid and meta_uid != user_id:
        raise HTTPException(403, "Payment does not belong to this account")
    if not meta_uid and pending and pending != reference:
        raise HTTPException(403, "Payment does not belong to this account")
    if reference != pending and pending:
        raise HTTPException(403, "Unknown payment reference for this account")

    auth = data.get("authorization") or {}
    auth_code = auth.get("authorization_code", "")
    customer = data.get("customer")
    customer_code = ""
    if isinstance(customer, dict):
        customer_code = (
            customer.get("customer_code")
            or customer.get("code")
            or (str(customer.get("id", "")) if customer.get("id") else "")
        )
    elif isinstance(customer, str):
        customer_code = customer
    if not customer_code and isinstance(data.get("customer"), dict):
        customer_code = data["customer"].get("customer_code", "")

    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id).first()
        if not row:
            raise HTTPException(404, "User not found")
        _activate_premium(row, authorization_code=auth_code, customer_code=customer_code[:80])
        try:
            _create_paystack_subscription(row, auth_code, row.email)
        except HTTPException as e:
            logger.warning("Paystack subscription create failed: %s", e.detail)
        db.flush()
        reconcile_user_plan(row)
        user_email = row.email
        user_name = row.name or ""

    from auth_service import get_user_by_id

    user_out = get_user_by_id(user_id)
    try:
        from email_service import send_payment_success
        send_payment_success(
            user_email,
            user_name,
            plan_id,
            int(plan.get("price_ngn") or 0),
        )
    except Exception:
        pass
    try:
        from audit_log import log_audit
        log_audit(
            action="billing.payment.success",
            resource_type="payment",
            resource_id=reference,
            detail=f"plan={plan_id} amount_kobo={expected}",
            user_id=user_id,
            user_email=user_email,
        )
    except Exception:
        pass

    return {"status": "success", "user": user_out, "amount_ngn": plan.get("price_ngn")}


def handle_webhook(payload: dict) -> dict:
    event = payload.get("event", "")
    data = payload.get("data") or {}

    if event == "charge.success":
        ref = data.get("reference", "")
        meta = data.get("metadata") or {}
        user_id = meta.get("user_id")
        if user_id:
            try:
                verify_payment(ref, user_id)
            except HTTPException:
                with get_db() as db:
                    row = db.query(User).filter(User.user_id == user_id).first()
                    if row and data.get("status") == "success":
                        auth = data.get("authorization") or {}
                        _activate_premium(
                            row,
                            authorization_code=auth.get("authorization_code", ""),
                        )
        return {"handled": True, "event": event}

    if event in ("subscription.disable", "subscription.not_renew"):
        code = data.get("subscription_code") or data.get("code")
        with get_db() as db:
            row = db.query(User).filter(User.paystack_subscription_code == code).first() if code else None
            if row:
                row.subscription_status = "cancelled"
                reconcile_user_plan(row)
        return {"handled": True, "event": event}

    if event in ("invoice.payment_failed", "charge.failed"):
        email = data.get("customer", {}).get("email") or data.get("email")
        with get_db() as db:
            row = db.query(User).filter(User.email == (email or "").lower()).first() if email else None
            if row and row.plan == "premium":
                row.subscription_status = "past_due"
                reconcile_user_plan(row)
        return {"handled": True, "event": event}

    if event in ("subscription.create", "subscription.notify"):
        code = data.get("subscription_code")
        with get_db() as db:
            row = db.query(User).filter(User.paystack_subscription_code == code).first() if code else None
            if row:
                row.subscription_status = "active"
                row.plan = "premium"
                nxt = data.get("next_payment_date")
                if nxt:
                    try:
                        from datetime import datetime

                        row.premium_until = int(datetime.fromisoformat(str(nxt).replace("Z", "+00:00")).timestamp())
                    except Exception:
                        row.premium_until = int(time.time()) + 32 * 86400
        return {"handled": True, "event": event}

    return {"handled": False, "event": event}


def verify_paystack_signature(body: bytes, signature: str) -> bool:
    if not PAYSTACK_SECRET or not signature:
        return False
    digest = hmac.new(PAYSTACK_SECRET.encode("utf-8"), body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(digest, signature)


def _lookup_paystack_customer_by_email(email: str) -> dict:
    if not paystack_configured():
        raise HTTPException(503, "Paystack not configured")
    import requests

    resp = requests.get(
        f"{PAYSTACK_BASE}/customer",
        params={"email": email.strip().lower()},
        headers={"Authorization": f"Bearer {PAYSTACK_SECRET}"},
        timeout=30,
    )
    try:
        payload = resp.json()
    except Exception:
        raise HTTPException(502, "Invalid Paystack response")
    if not resp.ok or not payload.get("status"):
        raise HTTPException(404, payload.get("message", "Customer not found on Paystack"))
    data = payload.get("data")
    if isinstance(data, list):
        return data[0] if data else {}
    return data if isinstance(data, dict) else {}


def charge_authorization(authorization_code: str, email: str, amount_kobo: int) -> dict:
    """Charge a saved card authorization (amount in kobo). Returns Paystack data."""
    if not authorization_code:
        raise HTTPException(400, "Missing authorization code")
    reference = f"akili_charge_{uuid.uuid4().hex[:20]}"
    payload = {
        "authorization_code": authorization_code,
        "email": (email or "").strip().lower(),
        "amount": int(amount_kobo or 0),
        "reference": reference,
    }
    data = _paystack("POST", "/transaction/charge_authorization", payload)
    # _paystack returns the inner data dict — attach reference for verification
    data["reference"] = reference
    return data


def run_charge_retry_batch(grace_days: int = 7) -> dict:
    """Attempt to charge stored authorizations for lapsed premium users within grace window.

    Looks for users whose `plan` was premium but `premium_until` has passed and within the grace window.
    For each user with a stored `paystack_authorization`, attempts `/transaction/charge_authorization` and
    calls `verify_payment` to reconcile the result.
    """
    from database import User, get_db

    now = int(time.time())
    grace = int(grace_days) * 86400
    attempted = 0
    succeeded = 0
    failed = 0
    skipped = 0

    with get_db() as db:
        rows = db.query(User).filter(
            User.is_active == True,
            User.plan == "premium",
            User.premium_until < now,
        ).all()

    for r in rows:
        attempted += 1
        try:
            # only retry within grace window
            if (now - int(getattr(r, "premium_until", 0) or 0)) > grace:
                skipped += 1
                continue
            auth_code = (getattr(r, "paystack_authorization", "") or "").strip()
            if not auth_code:
                failed += 1
                continue
            # Determine amount: prefer pending_plan_id if set, else default to premium_monthly
            plan_id = (getattr(r, "pending_plan_id", "") or "premium_monthly")
            plan = PLANS.get(plan_id) or PLANS.get("premium_monthly")
            amount = int(plan.get("price_kobo") or 0)
            payload = charge_authorization(auth_code, r.email, amount)
            ref = payload.get("reference")
            if not ref:
                failed += 1
                continue
            # verify and activate on success
            try:
                verify_payment(ref, r.user_id)
                succeeded += 1
            except Exception:
                failed += 1
        except Exception:
            failed += 1

    return {"attempted": attempted, "succeeded": succeeded, "failed": failed, "skipped": skipped}


def sync_user_paystack_codes(user_id: str) -> dict:
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id).first()
        if not row:
            raise HTTPException(404, "User not found")
        cust = _lookup_paystack_customer_by_email(row.email)
        code = (cust.get("customer_code") or cust.get("code") or "")[:80]
        if code:
            row.paystack_customer_code = code
        auth = (row.paystack_authorization or "").strip()
        if PAYSTACK_PREMIUM_PLAN and code and auth:
            try:
                _create_paystack_subscription(row, auth, row.email)
            except HTTPException:
                pass
        row.updated_at = int(time.time())
        return {
            "customer_code": row.paystack_customer_code or "",
            "subscription_code": row.paystack_subscription_code or "",
            "synced": bool(code),
        }


def cancel_subscription(user_id: str) -> dict:
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id).first()
        if not row:
            raise HTTPException(404, "User not found")
        code = (row.paystack_subscription_code or "").strip()
        if code and paystack_configured():
            try:
                _paystack("POST", "/subscription/disable", {"code": code})
            except HTTPException:
                pass
        row.subscription_status = "cancelled"
        reconcile_user_plan(row)
    from auth_service import get_user_by_id

    return {"status": "cancelled", "user": get_user_by_id(user_id)}
