"""Public pricing catalog (NGN) — Paystack charges amounts in kobo (×100)."""

CURRENCY = "NGN"

PLANS = {
    "trial": {
        "id": "trial",
        "name": "Trial",
        "price_ngn": 0,
        "price_kobo": 0,
        "interval": None,
        "description": "14 days — all modules unlocked when you sign up.",
        "highlights": ["All intelligence modules", "200 scans / month", "2 API keys"],
    },
    "premium_monthly": {
        "id": "premium_monthly",
        "name": "Premium",
        "price_ngn": 12000,
        "price_kobo": 1_200_000,
        "interval": "monthly",
        "description": "Full platform with monthly auto-debit via Paystack.",
        "highlights": [
            "All modules including org, graph, monitor, templates",
            "2,000 scans / month",
            "10 API keys",
            "Priority limits",
        ],
        "paystack_plan_env": "PAYSTACK_PREMIUM_PLAN_CODE",
    },
}



def pricing_payload() -> dict:
    from scan_profile import plan_comparison_rows, SCAN_PROFILES
    return {
        "currency": CURRENCY,
        "plans": PLANS,
        # Module-specific addons removed — all modules included in Premium
        "scan_profiles": {k: {"label": v["label"], "description": v["description"], "max_iterations": v["max_iterations"]} for k, v in SCAN_PROFILES.items()},
        "plan_comparison": plan_comparison_rows(),
        "note": "Premium includes all modules. Paystack handles card storage and monthly auto-debit.",
    }
