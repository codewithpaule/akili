"""Per-plan scan depth — tool count, AI loops, and baseline sets."""

from plans import effective_plan

# guest = no account quick scan; free/trial/premium = signed-in tiers
SCAN_PROFILES = {
    "guest": {
        "label": "Quick scan (no account)",
        "max_iterations": 0,
        "lite": True,
        "website_baseline": ["headers"],
        "email_baseline": ["email_intel"],
        "vulnerability_baseline": ["headers"],
        "ai_depth": "summary_only",
        "description": "Surface check only — 1–2 checks, no deep AI follow-up. Sign up for full scans.",
    },
    # 'free' tier removed — use 'trial' as the baseline for signed-in users during trial.
    "trial": {
        "label": "Trial",
        "max_iterations": 3,
        "lite": False,
        "website_baseline": ["ssl_check", "headers", "whois_check", "fingerprint", "ports"],
        "email_baseline": ["email_intel"],
        "vulnerability_baseline": ["vulnerability", "headers", "fingerprint"],
        "ai_depth": "enhanced",
        "description": "Baseline plus up to 3 AI-driven follow-up tools. All modules unlocked.",
    },
    "premium": {
        "label": "Premium",
        "max_iterations": 8,
        "lite": False,
        "website_baseline": ["ssl_check", "headers", "whois_check", "fingerprint", "ports", "exposed_files", "vulnerability"],
        "email_baseline": ["email_intel"],
        "vulnerability_baseline": ["vulnerability", "headers", "fingerprint", "exposed_files"],
        "ai_depth": "full",
        "description": "Full agent depth — exposed files, extended port checks, up to 8 AI follow-ups.",
    },
}


def tier_for_user(user: dict | None, *, guest: bool = False) -> str:
    if guest or not user:
        return "guest"
    return effective_plan(user)


def profile_for_tier(tier: str) -> dict:
    return dict(SCAN_PROFILES.get(tier, SCAN_PROFILES["trial"]))


def baseline_tools(module: str, tier: str) -> list[str]:
    p = profile_for_tier(tier)
    key = f"{module}_baseline"
    if key in p:
        return list(p[key])
    from agent import BASELINE_TOOLS
    base = list(BASELINE_TOOLS.get(module, ["headers"]))
    if tier == "guest":
        return base[:1]
    if tier == "trial":
        return base[:3] if module == "website" else base[:2]
    return base


def plan_comparison_rows() -> list[dict]:
    rows = []
    for tid in ("guest", "trial", "premium"):
        p = SCAN_PROFILES[tid]
        rows.append({
            "tier": tid,
            "name": p["label"],
            "ai_followups": p["max_iterations"],
            "website_checks": len(p.get("website_baseline", [])),
            "premium_modules": tid in ("trial", "premium"),
            "description": p["description"],
        })
    return rows
