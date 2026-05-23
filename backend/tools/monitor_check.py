import asyncio
from urllib.parse import urlparse

from tools.fingerprint import detect_technology_changes


async def run_quick_scan(target: str, target_type: str) -> dict:
    if target_type == "domain" and not target.startswith("http"):
        target = f"https://{target}"
    score = 70
    findings = []
    open_ports = []
    ssl = {}
    technologies = []

    if target_type in ("domain", "website") or target.startswith("http"):
        try:
            from tools import headers, ssl_check

            ctx = {}
            ssl_check.run(target, ctx)
            headers.run(target, ctx)
            ssl = ctx.get("tool_results", [{}])[0].get("raw", {}) if False else {}
            for tr in ctx.get("tool_results", []):
                pass
        except Exception:
            pass
        try:
            from tools.fingerprint import detect_technologies

            technologies, _ = await detect_technologies(target)
        except Exception:
            pass

    return {
        "score": score,
        "findings": findings,
        "open_ports": open_ports,
        "ssl": ssl,
        "technologies": technologies,
    }


async def run_monitor_check(target: str, target_type: str, previous_result: dict) -> dict:
    current = await run_quick_scan(target, target_type)
    alerts = []

    score_diff = current["score"] - previous_result.get("score", current["score"])
    if abs(score_diff) >= 10:
        alerts.append({
            "type": "score_change",
            "severity": "high" if score_diff < 0 else "info",
            "message": f"Security score changed {score_diff:+d} points ({previous_result.get('score')} → {current['score']})",
        })

    prev_titles = {f.get("title") or f.get("name") for f in previous_result.get("findings", [])}
    for finding in current.get("findings", []):
        title = finding.get("title") or finding.get("name")
        if title and title not in prev_titles and finding.get("severity") in ("critical", "high"):
            alerts.append({
                "type": "new_finding",
                "severity": finding["severity"],
                "message": f"New {finding['severity']} finding: {title}",
            })

    domain = target if target_type == "domain" else urlparse(target).hostname or target
    tech_changes = await detect_technology_changes(domain, current.get("technologies", []))
    for t in tech_changes:
        alerts.append({"type": "tech_change", "severity": t["severity"], "message": t["message"]})

    return {"alerts": alerts, "current_result": current, "checked_at": int(__import__("time").time())}
