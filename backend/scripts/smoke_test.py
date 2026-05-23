#!/usr/bin/env python3
"""Quick API smoke tests — run from backend/: python scripts/smoke_test.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

BASE = os.getenv("AKILI_API", "http://127.0.0.1:8001")


def ok(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    return cond


def main():
    print(f"AKILI smoke test @ {BASE}\n")
    all_ok = True

    r = requests.get(f"{BASE}/api/v1/health", timeout=10)
    all_ok &= ok("health", r.status_code == 200, r.json().get("api"))

    r = requests.get(f"{BASE}/api/v1/billing/pricing", timeout=10)
    data = r.json() if r.ok else {}
    prem = (data.get("plans") or {}).get("premium_monthly", {})
    all_ok &= ok("pricing premium", prem.get("price_ngn") == 12000, f"NGN {prem.get('price_ngn')}")

    r = requests.post(
        f"{BASE}/api/v1/auth/forgot-password",
        json={"email": "nobody@example.com"},
        timeout=10,
    )
    all_ok &= ok("forgot-password", r.status_code == 200)

    print("\nManual checks: login, developer keys, dashboard billing, admin-login.html")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
