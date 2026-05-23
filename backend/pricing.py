"""Public pricing catalog (NGN) — Paystack charges amounts in kobo (×100)."""

CURRENCY = "NGN"

PLANS = {
    "free": {
        "id": "free",
        "name": "Free",
        "price_ngn": 0,
        "price_kobo": 0,
        "interval": None,
        "description": "Core scans after your 14-day trial ends.",
        "highlights": ["Website, vuln, IP, person, email, domain", "50 scans / month", "1 API key"],
    },
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

# Optional per-module list prices (shown on pricing page; included in Premium)
MODULE_ADDONS = [
    {"module": "organization", "name": "Organization intel", "price_ngn": 4000},
    {"module": "company", "name": "Company intel", "price_ngn": 3500},
    {"module": "graph", "name": "Relationship graph", "price_ngn": 3000},
    {"module": "monitor", "name": "Continuous monitor", "price_ngn": 2500},
    {"module": "templates", "name": "Scan templates", "price_ngn": 2000},
    {"module": "auth", "name": "Authenticated scan", "price_ngn": 3500},
]


def pricing_payload() -> dict:
    from scan_profile import plan_comparison_rows, SCAN_PROFILES
    return {
        "currency": CURRENCY,
        "plans": PLANS,
        "module_addons": MODULE_ADDONS,
        "scan_profiles": {k: {"label": v["label"], "description": v["description"], "max_iterations": v["max_iterations"]} for k, v in SCAN_PROFILES.items()},
        "plan_comparison": plan_comparison_rows(),
        "note": "Premium includes all modules. Paystack handles card storage and monthly auto-debit.",
    }
