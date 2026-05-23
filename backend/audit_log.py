"""Persistent audit trail — actor, IP, action, resource."""

import json
import time
import uuid
from typing import Any, Optional

from fastapi import Request

from database import AuditLog, User, get_db


def client_ip(request: Optional[Request]) -> str:
    if not request:
        return ""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    if request.client:
        return (request.client.host or "")[:64]
    return ""


def log_audit(
    *,
    action: str,
    resource_type: str = "",
    resource_id: str = "",
    detail: str = "",
    user_id: str = "",
    user_email: str = "",
    ip_address: str = "",
    is_admin: bool = False,
    meta: Optional[dict] = None,
) -> None:
    action = (action or "unknown")[:80]
    with get_db() as db:
        db.add(AuditLog(
            log_id=str(uuid.uuid4()),
            timestamp=int(time.time()),
            user_id=(user_id or "")[:36],
            user_email=(user_email or "")[:254],
            ip_address=(ip_address or "")[:64],
            action=action,
            resource_type=(resource_type or "")[:40],
            resource_id=(resource_id or "")[:80],
            detail=(detail or "")[:2000],
            is_admin=bool(is_admin),
            meta_json=json.dumps(meta or {})[:8000],
        ))


def log_from_request(
    request: Request,
    action: str,
    *,
    admin_user: Optional[dict] = None,
    user: Optional[dict] = None,
    resource_type: str = "",
    resource_id: str = "",
    detail: str = "",
    meta: Optional[dict] = None,
) -> None:
    actor = admin_user or user or {}
    log_audit(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=detail,
        user_id=actor.get("user_id", ""),
        user_email=actor.get("email", ""),
        ip_address=client_ip(request),
        is_admin=bool(admin_user or actor.get("is_admin")),
        meta=meta,
    )


def list_audit_logs(*, page: int = 1, limit: int = 50, q: str = "", action: str = "") -> dict:
    limit = min(max(limit, 1), 100)
    page = max(page, 1)
    with get_db() as db:
        query = db.query(AuditLog)
        if q:
            like = f"%{q.strip()}%"
            query = query.filter(
                (AuditLog.user_email.ilike(like))
                | (AuditLog.detail.ilike(like))
                | (AuditLog.ip_address.ilike(like))
                | (AuditLog.action.ilike(like))
            )
        if action:
            query = query.filter(AuditLog.action == action[:80])
        total = query.count()
        rows = (
            query.order_by(AuditLog.timestamp.desc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        items = [{
            "log_id": r.log_id,
            "timestamp": r.timestamp,
            "user_id": r.user_id,
            "user_email": r.user_email,
            "ip_address": r.ip_address,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "detail": r.detail,
            "is_admin": r.is_admin,
        } for r in rows]
    return {"items": items, "total": total, "page": page, "limit": limit}
