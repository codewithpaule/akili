import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from database import get_db, AuditLog

with get_db() as db:
    rows = db.query(AuditLog).filter(AuditLog.action=='auth.api_key.invalid').order_by(AuditLog.timestamp.desc()).limit(5).all()
    for r in rows:
        print(r.timestamp, r.user_id, r.user_email, r.ip_address, r.action, r.detail[:200])
