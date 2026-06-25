"""Per-plan scan depth — tool count, AI loops, and baseline sets."""

# guest = no account quick scan; account = signed-in deep scans
SCAN_PROFILES = {
    "guest": {
        "label": "Quick scan (no account)",
        "max_iterations": 8,
        "lite": True,
        "max_plan_tools": 4,
        "ai_depth": "agent_lite",
        "description": "Planning-first agent with up to 4 focused checks and live follow-up. Sign up for full depth.",
    },
    "account": {
        "label": "Full investigation",
        "max_iterations": 24,
        "lite": False,
        "max_plan_tools": 10,
        "ai_depth": "deep",
        "description": "Senior-analyst depth: multi-tool planning, confidence-driven follow-ups, CVE/version chaining, web intel when evidence is thin.",
    },
}


def tier_for_user(user: dict | None, *, guest: bool = False) -> str:
    if guest or not user:
        return "guest"
    return "account"


def profile_for_tier(tier: str) -> dict:
    if tier in ("trial", "premium"):
        tier = "account"
    return dict(SCAN_PROFILES.get(tier, SCAN_PROFILES["account"]))


def baseline_tools(module: str, tier: str) -> list[str]:
    """Planning-first agent selects tools dynamically; no fixed baseline."""
    return []


def plan_comparison_rows() -> list[dict]:
    rows = []
    for tid in ("guest", "account"):
        p = SCAN_PROFILES[tid]
        rows.append({
            "tier": tid,
            "name": p["label"],
            "ai_followups": p["max_iterations"],
            "planned_tools": p.get("max_plan_tools", 0),
            "premium_modules": False,
            "description": p["description"],
        })
    return rows
