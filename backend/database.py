import json
import os
import secrets
import time
from contextlib import contextmanager
from typing import Any, Optional
from datetime import datetime, timedelta

from dotenv import load_dotenv
from sqlalchemy import Boolean, Column, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import QueuePool

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://neondb_owner:npg_oaTemFVS0dJ2@ep-solitary-silence-aqnbwktz-pooler.c-8.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require")

if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine = create_engine(DATABASE_URL, connect_args=connect_args)
else:
    # PostgreSQL with SSL connection pool settings for cloud environments
    engine = create_engine(
        DATABASE_URL,
        poolclass=QueuePool,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,  # Verify connections before using
        pool_recycle=3600,  # Recycle connections after 1 hour
        connect_args={
            "sslmode": "require",
            "connect_timeout": 10,
        }
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

sessions: dict[str, dict] = {}


class Scan(Base):
    __tablename__ = "scans"

    scan_id = Column(String, primary_key=True)
    user_id = Column(String, default="")
    scan_type = Column(String, nullable=False)
    target = Column(Text, nullable=False)
    timestamp = Column(Integer, nullable=False)
    score = Column(Integer, default=0)
    grade = Column(String, nullable=True)
    findings_json = Column(Text, default="{}")
    ai_summary = Column(Text, default="")
    tool_count = Column(Integer, default=0)
    duration_ms = Column(Integer, default=0)
    share_token = Column(String, default="")


class User(Base):
    __tablename__ = "users"

    user_id = Column(String, primary_key=True)
    email = Column(String, nullable=False, unique=True)
    password_hash = Column(String, default="")
    name = Column(String, default="")
    plan = Column(String, default="account")
    trial_ends_at = Column(Integer, default=0)
    google_id = Column(String, default="")
    phone = Column(String, default="")
    organization = Column(String, default="")
    job_title = Column(String, default="")
    country = Column(String, default="")
    avatar_url = Column(Text, default="")
    usage_identity = Column(String, default="")
    updated_at = Column(Integer, default=0)
    created_at = Column(Integer, nullable=False)
    is_active = Column(Boolean, default=True)
    plan_before_premium = Column(String, default="")
    subscription_status = Column(String, default="")
    premium_until = Column(Integer, default=0)
    paystack_authorization = Column(String, default="")
    paystack_customer_code = Column(String, default="")
    paystack_subscription_code = Column(String, default="")
    pending_payment_ref = Column(String, default="")
    pending_plan_id = Column(String, default="")
    role = Column(String, default="user")
    password_reset_hash = Column(String, default="")
    password_reset_expires = Column(Integer, default=0)
    renewal_reminder_at = Column(Integer, default=0)
    email_verified = Column(Boolean, default=False)
    email_verify_hash = Column(String, default="")
    daily_scan_limit = Column(Integer, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id = Column(String, primary_key=True)
    timestamp = Column(Integer, nullable=False)
    user_id = Column(String, default="")
    user_email = Column(String, default="")
    ip_address = Column(String, default="")
    action = Column(String, nullable=False)
    resource_type = Column(String, default="")
    resource_id = Column(String, default="")
    detail = Column(Text, default="")
    is_admin = Column(Boolean, default=False)
    meta_json = Column(Text, default="{}")


class UsageCounter(Base):
    __tablename__ = "usage_counters"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, nullable=False)
    period = Column(String, nullable=False)
    module = Column(String, nullable=False)
    count = Column(Integer, default=0)


class ApiKey(Base):
    __tablename__ = "api_keys"

    key_id = Column(String, primary_key=True)
    user_id = Column(String, default="")
    key_name = Column(String, default="")
    key_hash = Column(String, nullable=False, unique=True)
    key_preview = Column(String, nullable=False)
    tier = Column(String, default="account")
    created_at = Column(Integer, nullable=False)
    last_used = Column(Integer, default=0)
    requests_today = Column(Integer, default=0)
    requests_month = Column(Integer, default=0)
    is_sandbox = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)


class Monitor(Base):
    __tablename__ = "monitors"

    monitor_id = Column(String, primary_key=True)
    target = Column(Text, nullable=False)
    target_type = Column(String, nullable=False)
    frequency = Column(String, default="weekly")
    last_checked = Column(Integer, default=0)
    last_score = Column(Integer, default=0)
    alert_email = Column(String, default="")
    is_active = Column(Boolean, default=True)


class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    subject = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    timestamp = Column(Integer, nullable=False)


class PhoneQuery(Base):
    __tablename__ = "phone_queries"

    query_id = Column(String, primary_key=True)
    normalized = Column(String, nullable=False)
    raw_input = Column(String, nullable=False)
    user_id = Column(String, default="")
    api_key_id = Column(String, default="")
    summary_json = Column(Text, default="{}")
    social_matches = Column(Text, default="[]")
    sources = Column(Text, default="[]")
    risk_score = Column(Integer, default=0)
    created_at = Column(Integer, nullable=False)


class PhoneQueryLog(Base):
    __tablename__ = "phone_query_logs"

    log_id = Column(String, primary_key=True)
    query_id = Column(String, default="")
    actor_user_id = Column(String, default="")
    actor_api_key = Column(String, default="")
    action = Column(String, default="search")
    request_ip = Column(String, default="")
    note = Column(Text, default="")
    redacted = Column(Boolean, default=False)
    created_at = Column(Integer, nullable=False)


class ScanUsage(Base):
    __tablename__ = "scan_usage"

    user_id = Column(String, primary_key=True)
    date = Column(String, primary_key=True)
    scan_count = Column(Integer, default=0)


class Reservation(Base):
    __tablename__ = "scan_reservations"

    reservation_id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    scan_id = Column(String, default="")
    created_at = Column(Integer, nullable=False)
    expires_at = Column(Integer, default=0)


def _table_columns(conn, table: str) -> set[str]:
    from sqlalchemy import inspect

    return {c["name"] for c in inspect(conn).get_columns(table)}


def migrate_schema():
    """Add columns to existing SQLite DBs (create_all does not alter tables)."""
    from sqlalchemy import inspect, text

    with engine.connect() as conn:
        insp = inspect(conn)
        tables = set(insp.get_table_names())

        def add_col(table: str, col: str, ddl: str):
            if table not in tables:
                return
            cols = _table_columns(conn, table)
            if col in cols:
                return
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))
            conn.commit()

        add_col("api_keys", "user_id", "VARCHAR DEFAULT ''")
        add_col("api_keys", "key_name", "VARCHAR DEFAULT ''")
        add_col("scans", "user_id", "VARCHAR DEFAULT ''")
        add_col("scans", "share_token", "VARCHAR DEFAULT ''")
        add_col("users", "plan_before_premium", "VARCHAR DEFAULT ''")
        add_col("users", "subscription_status", "VARCHAR DEFAULT ''")
        add_col("users", "premium_until", "INTEGER DEFAULT 0")
        add_col("users", "paystack_authorization", "VARCHAR DEFAULT ''")
        add_col("users", "paystack_customer_code", "VARCHAR DEFAULT ''")
        add_col("users", "paystack_subscription_code", "VARCHAR DEFAULT ''")
        add_col("users", "pending_payment_ref", "VARCHAR DEFAULT ''")
        add_col("users", "pending_plan_id", "VARCHAR DEFAULT ''")
        add_col("users", "phone", "VARCHAR DEFAULT ''")
        add_col("users", "organization", "VARCHAR DEFAULT ''")
        add_col("users", "job_title", "VARCHAR DEFAULT ''")
        add_col("users", "country", "VARCHAR DEFAULT ''")
        add_col("users", "avatar_url", "TEXT DEFAULT ''")
        add_col("users", "usage_identity", "VARCHAR DEFAULT ''")
        add_col("users", "updated_at", "INTEGER DEFAULT 0")
        add_col("users", "role", "VARCHAR DEFAULT 'user'")
        add_col("users", "password_reset_hash", "VARCHAR DEFAULT ''")
        add_col("users", "password_reset_expires", "INTEGER DEFAULT 0")
        add_col("users", "renewal_reminder_at", "INTEGER DEFAULT 0")
        add_col("users", "email_verified", "BOOLEAN DEFAULT 0")
        add_col("users", "email_verify_hash", "VARCHAR DEFAULT ''")
        add_col("users", "admin_otp_hash", "VARCHAR DEFAULT ''")
        add_col("users", "admin_otp_expires", "INTEGER DEFAULT 0")
        add_col("users", "daily_scan_limit", "INTEGER DEFAULT NULL")
        
        # Create scan_usage table if it doesn't exist
        if "scan_usage" not in tables:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS scan_usage (
                    user_id TEXT NOT NULL,
                    date TEXT NOT NULL,
                    scan_count INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, date)
                )
            """))
            conn.commit()
        # Create scan_logs table if it doesn't exist
        if "scan_logs" not in tables:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    log_id TEXT PRIMARY KEY,
                    scan_id TEXT DEFAULT '',
                    timestamp INTEGER NOT NULL,
                    kind TEXT DEFAULT '',
                    message TEXT DEFAULT ''
                )
            """))
            conn.commit()


def init_db():
    Base.metadata.create_all(bind=engine)
    migrate_schema()
    try:
        from admin_service import bootstrap_admin_user
        bootstrap_admin_user()
    except Exception:
        pass


@contextmanager
def get_db():
    db = SessionLocal()
    db.engine = engine
    try:
        yield db
        db.commit()
    except Exception as e:
        db.rollback()
        # Retry once for transient connection errors
        if "SSL connection has been closed" in str(e) or "connection" in str(e).lower():
            try:
                db.close()
                db = SessionLocal()
                yield db
                db.commit()
            except Exception:
                raise
        raise
    finally:
        db.close()


def create_session(scan_id: str, scan_type: str, target: str):
    sessions[scan_id] = {"scan_id": scan_id, "scan_type": scan_type, "started_at": int(time.time())}


def save_scan(
    scan_id: str,
    scan_type: str,
    target: str,
    report: dict,
    tool_count: int = 0,
    duration_ms: int = 0,
    user_id: str = "",
):
    blob = json.dumps(report)
    score = int(report.get("score", 0) or 0)
    grade = report.get("grade")
    summary = report.get("summary") or report.get("ai_summary") or report.get("overall_assessment", "")

    with get_db() as db:
        row = Scan(
            scan_id=scan_id,
            user_id=(user_id or "")[:36],
            scan_type=scan_type,
            target=target[:500],
            timestamp=int(time.time()),
            score=score,
            grade=grade,
            findings_json=blob,
            ai_summary=str(summary)[:15000],
            tool_count=tool_count,
            duration_ms=duration_ms,
        )
        db.merge(row)
    sessions.pop(scan_id, None)


def _report_from_row(row: Scan, *, public: bool = False) -> dict:
    try:
        data = json.loads(row.findings_json or "{}")
    except json.JSONDecodeError:
        data = {}
    out = {
        "scan_id": row.scan_id,
        "scan_type": row.scan_type,
        "target": row.target,
        "timestamp": row.timestamp,
        "score": row.score,
        "grade": row.grade,
        "ai_summary": row.ai_summary,
        "tool_count": row.tool_count,
        "duration_ms": row.duration_ms,
        **data,
    }
    if public:
        out.pop("user_id", None)
    else:
        out["user_id"] = row.user_id or ""
        token = (row.share_token or "").strip()
        if token:
            out["share_token"] = token
    return out


def get_report(scan_id: str) -> Optional[dict]:
    with get_db() as db:
        row = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not row:
            return None
        return _report_from_row(row, public=False)


def get_report_by_share_token(share_token: str) -> Optional[dict]:
    token = (share_token or "").strip()
    if len(token) < 16:
        return None
    with get_db() as db:
        row = db.query(Scan).filter(Scan.share_token == token).first()
        if not row:
            return None
        return _report_from_row(row, public=True)


def enable_report_share(scan_id: str, user_id: str) -> Optional[str]:
    with get_db() as db:
        row = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not row:
            return None
        owner = (row.user_id or "").strip()
        if owner and owner != user_id:
            return None
        if not row.share_token:
            row.share_token = secrets.token_urlsafe(24)
        return row.share_token


def list_history(limit=20, offset=0, scan_type=None, query=None, user_id: str = ""):
    with get_db() as db:
        q = db.query(Scan)
        if user_id:
            q = q.filter(Scan.user_id == user_id)
        if scan_type and scan_type != "all":
            q = q.filter(Scan.scan_type == scan_type)
        if query:
            q = q.filter(Scan.target.ilike(f"%{query}%"))
        total = q.count()
        rows = q.order_by(Scan.timestamp.desc()).offset(offset).limit(limit).all()
        items = []
        for r in rows:
            t = r.target if len(r.target) <= 60 else r.target[:57] + "..."
            items.append({
                "scan_id": r.scan_id,
                "scan_type": r.scan_type,
                "target": t,
                "score": r.score,
                "grade": r.grade,
                "timestamp": r.timestamp,
            })
        return items, total


def delete_scan(scan_id: str, user_id: str = "") -> bool:
    with get_db() as db:
        q = db.query(Scan).filter(Scan.scan_id == scan_id)
        if user_id:
            q = q.filter(Scan.user_id == user_id)
        n = q.delete()
        return n > 0


def delete_all_scans(user_id: str = "") -> int:
    with get_db() as db:
        q = db.query(Scan)
        if user_id:
            q = q.filter(Scan.user_id == user_id)
        return q.delete()


def get_user_row(user_id: str) -> Optional[User]:
    with get_db() as db:
        return db.query(User).filter(User.user_id == user_id, User.is_active == True).first()


def update_user_profile(user_id: str, fields: dict) -> Optional[User]:
    allowed = {"name", "phone", "organization", "job_title", "country"}
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id, User.is_active == True).first()
        if not row:
            return None
        for key, val in fields.items():
            if key not in allowed:
                continue
            setattr(row, key, str(val or "")[:200] if key != "name" else str(val or "")[:120])
        row.updated_at = int(time.time())
        db.flush()
        return row


def save_contact(name: str, email: str, subject: str, message: str):
    with get_db() as db:
        db.add(Contact(
            name=name[:100],
            email=email[:200],
            subject=subject[:200],
            message=message[:5000],
            timestamp=int(time.time()),
        ))


def list_monitors():
    with get_db() as db:
        rows = db.query(Monitor).filter(Monitor.is_active == True).all()
        return [{
            "monitor_id": m.monitor_id,
            "target": m.target,
            "target_type": m.target_type,
            "frequency": m.frequency,
            "last_checked": m.last_checked,
            "last_score": m.last_score,
            "alert_email": m.alert_email,
        } for m in rows]


def save_monitor(monitor_id: str, target: str, target_type: str, frequency: str, alert_email: str):
    with get_db() as db:
        db.merge(Monitor(
            monitor_id=monitor_id,
            target=target[:500],
            target_type=target_type,
            frequency=frequency,
            last_checked=0,
            last_score=0,
            alert_email=alert_email[:200],
            is_active=True,
        ))


# --- Extended schema (CVE section and below) ---


class TechSnapshot(Base):
    __tablename__ = "tech_snapshots"

    snapshot_id = Column(String, primary_key=True)
    domain = Column(String, nullable=False)
    scan_id = Column(String, default="")
    timestamp = Column(Integer, nullable=False)
    technologies = Column(Text, default="[]")


class ScoreHistory(Base):
    __tablename__ = "score_history"

    id = Column(String, primary_key=True)
    domain = Column(String, nullable=False)
    scan_id = Column(String, default="")
    timestamp = Column(Integer, nullable=False)
    score = Column(Integer, default=0)
    grade = Column(String, nullable=True)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)


class FindingStatus(Base):
    __tablename__ = "finding_status"

    finding_id = Column(String, primary_key=True)
    scan_id = Column(String, default="")
    domain = Column(String, default="")
    finding_title = Column(Text, nullable=False)
    severity = Column(String, default="info")
    status = Column(String, default="open")
    updated_at = Column(Integer, nullable=False)
    note = Column(Text, default="")


class VerifiedDomain(Base):
    __tablename__ = "verified_domains"

    domain = Column(String, primary_key=True)
    verify_token = Column(String, nullable=False)
    verified_at = Column(Integer, default=0)
    verified = Column(Boolean, default=False)


class AgencyProfile(Base):
    __tablename__ = "agency_profiles"

    profile_id = Column(String, primary_key=True)
    api_key_id = Column(String, default="")
    company_name = Column(String, default="")
    logo_base64 = Column(Text, default="")
    primary_color = Column(String, default="#2563EB")
    contact_email = Column(String, default="")
    website = Column(String, default="")


class MonitorAlert(Base):
    __tablename__ = "monitor_alerts"

    alert_id = Column(String, primary_key=True)
    monitor_id = Column(String, default="")
    timestamp = Column(Integer, nullable=False)
    severity = Column(String, default="info")
    alert_type = Column(String, default="")
    message = Column(Text, default="")
    is_read = Column(Boolean, default=False)


class LLMCall(Base):
    __tablename__ = "llm_calls"

    call_id = Column(String, primary_key=True)
    timestamp = Column(Integer, nullable=False)
    provider = Column(String, default="")
    model = Column(String, default="")
    prompt = Column(Text, default="")
    response = Column(Text, default="")
    parsed_json = Column(Text, default="{}")
    meta_json = Column(Text, default="{}")


class ScanLog(Base):
    __tablename__ = "scan_logs"

    log_id = Column(String, primary_key=True)
    scan_id = Column(String, default="")
    timestamp = Column(Integer, nullable=False)
    kind = Column(String, default="")
    message = Column(Text, default="")


def save_tech_snapshot(snapshot_id: str, domain: str, scan_id: str, technologies: list):
    with get_db() as db:
        db.add(TechSnapshot(
            snapshot_id=snapshot_id,
            domain=domain[:253],
            scan_id=scan_id,
            timestamp=int(time.time()),
            technologies=json.dumps(technologies),
        ))


def get_last_tech_snapshot(domain: str) -> Optional[list]:
    with get_db() as db:
        rows = (
            db.query(TechSnapshot)
            .filter(TechSnapshot.domain == domain)
            .order_by(TechSnapshot.timestamp.desc())
            .limit(2)
            .all()
        )
        if len(rows) < 2:
            return None
        try:
            return json.loads(rows[1].technologies or "[]")
        except json.JSONDecodeError:
            return None


def save_score_history(entry_id: str, domain: str, scan_id: str, report: dict):
    findings = report.get("findings", [])
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev in counts:
            counts[sev] += 1
    with get_db() as db:
        db.add(ScoreHistory(
            id=entry_id,
            domain=domain[:253],
            scan_id=scan_id,
            timestamp=int(time.time()),
            score=int(report.get("score", 0) or 0),
            grade=report.get("grade"),
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
        ))


def get_score_history(domain: str, limit: int = 12) -> list[dict]:
    with get_db() as db:
        rows = (
            db.query(ScoreHistory)
            .filter(ScoreHistory.domain == domain)
            .order_by(ScoreHistory.timestamp.asc())
            .limit(limit)
            .all()
        )
        return [{
            "timestamp": r.timestamp,
            "score": r.score,
            "grade": r.grade,
            "critical_count": r.critical_count,
            "high_count": r.high_count,
        } for r in rows]


def upsert_finding_status(
    finding_id: str,
    scan_id: str,
    domain: str,
    title: str,
    severity: str,
    status: str,
    note: str = "",
):
    with get_db() as db:
        db.merge(FindingStatus(
            finding_id=finding_id,
            scan_id=scan_id,
            domain=domain[:253],
            finding_title=title[:500],
            severity=severity,
            status=status,
            updated_at=int(time.time()),
            note=note[:2000],
        ))


def get_finding_status(finding_id: str) -> Optional[dict]:
    with get_db() as db:
        row = db.query(FindingStatus).filter(FindingStatus.finding_id == finding_id).first()
        if not row:
            return None
        return {
            "finding_id": row.finding_id,
            "status": row.status,
            "note": row.note,
            "finding_title": row.finding_title,
        }


def remediation_progress(domain: str) -> dict:
    with get_db() as db:
        rows = db.query(FindingStatus).filter(FindingStatus.domain == domain).all()
        if not rows:
            return {"total": 0, "resolved": 0, "percent": 0}
        fixed = sum(1 for r in rows if r.status in ("fixed", "accepted"))
        return {"total": len(rows), "resolved": fixed, "percent": int(100 * fixed / len(rows)) if rows else 0}


def create_domain_verification(domain: str, token: str):
    with get_db() as db:
        db.merge(VerifiedDomain(
            domain=domain[:253],
            verify_token=token,
            verified_at=0,
            verified=False,
        ))


def get_domain_verification(domain: str) -> Optional[dict]:
    with get_db() as db:
        row = db.query(VerifiedDomain).filter(VerifiedDomain.domain == domain).first()
        if not row:
            return None
        return {
            "domain": row.domain,
            "verify_token": row.verify_token,
            "verified": row.verified,
            "verified_at": row.verified_at,
        }


def mark_domain_verified(domain: str):
    with get_db() as db:
        row = db.query(VerifiedDomain).filter(VerifiedDomain.domain == domain).first()
        if row:
            row.verified = True
            row.verified_at = int(time.time())


def save_agency_profile(profile_id: str, api_key_id: str, data: dict):
    with get_db() as db:
        db.merge(AgencyProfile(
            profile_id=profile_id,
            api_key_id=api_key_id,
            company_name=data.get("company_name", "")[:200],
            logo_base64=data.get("logo_base64", "")[:500000],
            primary_color=data.get("primary_color", "#2563EB")[:20],
            contact_email=data.get("contact_email", "")[:200],
            website=data.get("website", "")[:300],
        ))


def get_agency_profile(api_key_id: str) -> Optional[dict]:
    with get_db() as db:
        row = db.query(AgencyProfile).filter(AgencyProfile.api_key_id == api_key_id).first()
        if not row:
            return None
        return {
            "profile_id": row.profile_id,
            "company_name": row.company_name,
            "logo_base64": row.logo_base64,
            "primary_color": row.primary_color,
            "contact_email": row.contact_email,
            "website": row.website,
        }


def save_monitor_alert(alert_id: str, monitor_id: str, severity: str, alert_type: str, message: str):
    with get_db() as db:
        db.add(MonitorAlert(
            alert_id=alert_id,
            monitor_id=monitor_id,
            timestamp=int(time.time()),
            severity=severity,
            alert_type=alert_type,
            message=message[:1000],
            is_read=False,
        ))


def save_llm_call(provider: str, model: str, prompt: str, response: str, parsed: dict | None, meta: dict | None = None):
    from datetime import datetime
    with get_db() as db:
        try:
            db.add(LLMCall(
                call_id=secrets.token_urlsafe(16),
                timestamp=int(time.time()),
                provider=(provider or "")[:80],
                model=(model or "")[:120],
                prompt=(prompt or "")[:8000],
                response=(response or "")[:8000],
                parsed_json=json.dumps(parsed or {})[:16000],
                meta_json=json.dumps(meta or {})[:16000],
            ))
        except Exception:
            db.rollback()


def append_scan_log(scan_id: str, kind: str, message: str):
    """Append a scan log message (used by agent streaming)."""
    try:
        import logging
        logging.getLogger('akili.db').debug('append_scan_log %s %s', scan_id, (kind or '')[:40])
    except Exception:
        pass
    with get_db() as db:
        try:
            db.add(ScanLog(
                log_id=secrets.token_urlsafe(12),
                scan_id=scan_id,
                timestamp=int(time.time()),
                kind=(kind or "")[:80],
                message=(message or "")[:20000],
            ))
        except Exception:
            db.rollback()


def get_scan_logs(scan_id: str, since: int = 0, limit: int = 500) -> list[dict]:
    with get_db() as db:
        q = db.query(ScanLog).filter(ScanLog.scan_id == scan_id)
        if since:
            q = q.filter(ScanLog.timestamp > int(since))
        rows = q.order_by(ScanLog.timestamp.asc()).limit(limit).all()
        return [{
            "log_id": r.log_id,
            "scan_id": r.scan_id,
            "timestamp": r.timestamp,
            "kind": r.kind,
            "message": r.message,
        } for r in rows]


def list_monitor_alerts(limit: int = 50) -> list[dict]:
    with get_db() as db:
        rows = db.query(MonitorAlert).order_by(MonitorAlert.timestamp.desc()).limit(limit).all()
        return [{
            "alert_id": r.alert_id,
            "monitor_id": r.monitor_id,
            "timestamp": r.timestamp,
            "severity": r.severity,
            "alert_type": r.alert_type,
            "message": r.message,
            "is_read": r.is_read,
        } for r in rows]


def period_key() -> str:
    import datetime
    # Use a daily period key so usage limits are enforced per-day
    return datetime.datetime.utcnow().strftime("%Y-%m-%d")


def increment_usage(user_id: str, module: str) -> int:
    period = period_key()
    with get_db() as db:
        row = (
            db.query(UsageCounter)
            .filter(UsageCounter.user_id == user_id, UsageCounter.period == period, UsageCounter.module == module)
            .first()
        )
        if row:
            row.count = (row.count or 0) + 1
            return row.count
        db.add(UsageCounter(user_id=user_id, period=period, module=module, count=1))
        return 1


def get_usage_summary(user_id: str) -> dict:
    period = period_key()
    with get_db() as db:
        rows = db.query(UsageCounter).filter(
            UsageCounter.user_id == user_id, UsageCounter.period == period
        ).all()
        return {r.module: r.count for r in rows}


def count_user_keys(user_id: str) -> int:
    with get_db() as db:
        return db.query(ApiKey).filter(ApiKey.user_id == user_id, ApiKey.is_active == True).count()


def delete_monitor(monitor_id: str) -> bool:
    with get_db() as db:
        row = db.query(Monitor).filter(Monitor.monitor_id == monitor_id).first()
        if not row:
            return False
        row.is_active = False
        return True


init_db()


def save_phone_query(query_id: str, normalized: str, raw_input: str, result: dict, user_id: str = "", api_key_id: str = ""):
    with get_db() as db:
        db.merge(PhoneQuery(
            query_id=query_id,
            normalized=(normalized or "")[:120],
            raw_input=(raw_input or "")[:200],
            user_id=(user_id or "")[:36],
            api_key_id=(api_key_id or "")[:80],
            summary_json=json.dumps({
                "social_matches": result.get("social_matches", []),
                "search_source": result.get("search_source", ""),
            })[:16000],
            social_matches=json.dumps(result.get("social_matches", []) )[:16000],
            sources=json.dumps(result.get("evidence", []) )[:16000],
            risk_score=int(result.get("risk_score", 0) or 0),
            created_at=int(time.time()),
        ))


def log_phone_query(query_id: str, actor_user_id: str, actor_api_key: str, action: str = "search", request_ip: str = "", note: str = "", redacted: bool = False):
    with get_db() as db:
        db.add(PhoneQueryLog(
            log_id=secrets.token_urlsafe(12),
            query_id=query_id,
            actor_user_id=(actor_user_id or "")[:36],
            actor_api_key=(actor_api_key or "")[:80],
            action=action[:40],
            request_ip=(request_ip or "")[:80],
            note=(note or "")[:1000],
            redacted=bool(redacted),
            created_at=int(time.time()),
        ))


def get_daily_scan_count(user_id: str) -> int:
    from datetime import datetime
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with get_db() as db:
        row = db.query(ScanUsage).filter(
            ScanUsage.user_id == user_id,
            ScanUsage.date == today
        ).first()
        return row.scan_count if row else 0


def check_and_increment_scan_limit(user_id: str) -> int:
    from datetime import datetime
    from fastapi import HTTPException
    
    today = datetime.utcnow().strftime("%Y-%m-%d")
    
    with get_db() as db:
        usage = db.query(ScanUsage).filter(
            ScanUsage.user_id == user_id,
            ScanUsage.date == today
        ).first()
        
        count = usage.scan_count if usage else 0
        
        from plans import ACCOUNT_DAILY_SCAN_LIMIT

        # Prefer a per-user override if configured
        user_limit = None
        try:
            with get_db() as db:
                u = db.query(User).filter(User.user_id == user_id).first()
                if u and u.daily_scan_limit:
                    user_limit = int(u.daily_scan_limit)
        except Exception:
            user_limit = None

        effective_limit = user_limit if user_limit is not None else ACCOUNT_DAILY_SCAN_LIMIT

        if count >= effective_limit:
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "daily_limit_reached",
                        "message": f"{effective_limit} daily account scans used. Resets at midnight UTC.",
                        "used": count,
                        "limit": effective_limit,
                        "resets_at": get_midnight_utc()
                    }
                )
        
        if usage:
            usage.scan_count = count + 1
        else:
            db.add(ScanUsage(user_id=user_id, date=today, scan_count=1))
        
        return count + 1


def get_midnight_utc() -> int:
    from datetime import datetime, timedelta
    tomorrow = (datetime.utcnow() + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(tomorrow.timestamp())


def reserve_scan_slot(user_id: str, ttl: int = 300) -> dict:
    """Reserve a scan slot for a user by incrementing the daily counter and returning a reservation id.
    This consumes one of the user's daily scans immediately. Caller should present the reservation to the scan request.
    """
    from datetime import datetime
    rid = secrets.token_urlsafe(12)
    now = int(time.time())
    expires = int((datetime.utcnow() + timedelta(seconds=ttl)).timestamp())
    # Increment the daily scan count (this will raise HTTPException if over limit)
    count = check_and_increment_scan_limit(user_id)
    with get_db() as db:
        try:
            db.add(Reservation(
                reservation_id=rid,
                user_id=user_id,
                scan_id="",
                created_at=now,
                expires_at=expires,
            ))
        except Exception:
            db.rollback()
    return {"reservation_id": rid, "expires_at": expires, "consumed_count": count}


def consume_reservation(reservation_id: str, user_id: str) -> bool:
    """Mark reservation as consumed (delete) if it exists and belongs to user_id."""
    with get_db() as db:
        row = db.query(Reservation).filter(Reservation.reservation_id == reservation_id, Reservation.user_id == user_id).first()
        if not row:
            return False
        db.delete(row)
        return True
