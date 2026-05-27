"""Pricing disabled for this deployment.

This deployment operates as a free-tier-only service; billing and Paystack
integration have been removed. Keep this module present so existing imports
work, but return a minimal payload indicating billing is disabled.
"""

def pricing_payload() -> dict:
    return {
        "currency": None,
        "plans": {},
        "scan_profiles": {},
        "plan_comparison": [],
        "note": "Billing and paid plan upgrades are disabled on this deployment. Accounts receive 5 scans per day.",
        "billing_disabled": True,
    }

# Backwards compatibility: some modules import `PLANS` directly.
# Keep an empty mapping so imports succeed but indicate billing is disabled.
PLANS: dict = {}
