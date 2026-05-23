import asyncio
import json
from typing import AsyncGenerator

SCENARIOS = {
    "clean_scan": {
        "grade": "A",
        "score": 92,
        "summary": "Sandbox: No significant issues detected.",
        "findings": [{"severity": "INFO", "name": "Clean scan", "explanation": "Mock clean result.", "recommendation": "Continue monitoring."}],
    },
    "critical_vulns": {
        "grade": "F",
        "score": 28,
        "summary": "Sandbox: Critical exposure detected.",
        "findings": [
            {"severity": "CRITICAL", "name": "Exposed database port", "explanation": "Port 3306 open.", "recommendation": "Close immediately.", "cvss": 9.1},
            {"severity": "HIGH", "name": "Missing CSP", "explanation": "No Content-Security-Policy.", "recommendation": "Add CSP header.", "cvss": 6.5},
        ],
        "ports": [{"port": 3306, "service": "MySQL", "status": "open", "risk": "CRITICAL"}],
    },
    "high_confidence_person": {
        "name": "Alex Developer",
        "confidence": 88,
        "score": 88,
        "platforms": {"linkedin": {"found": True, "url": "https://linkedin.com/in/alex"}, "github": {"found": True, "url": "https://github.com/alex"}},
        "trust_signals": ["LinkedIn active since 2018", "GitHub 200+ commits"],
        "red_flags": [],
        "ai_summary": "Sandbox: Strong public professional presence.",
        "overall_assessment": "Proceed with standard due diligence.",
    },
    "low_confidence_person": {
        "name": "Common Name",
        "confidence": 22,
        "score": 22,
        "platforms": {"linkedin": {"found": False}, "github": {"found": False}},
        "trust_signals": [],
        "red_flags": ["Limited public data", "Name may match many individuals"],
        "ai_summary": "Sandbox: Insufficient public data.",
        "overall_assessment": "Verify further before engaging.",
    },
    "malicious_ip": {
        "grade": "F",
        "score": 15,
        "summary": "Sandbox: IP flagged in threat feeds.",
        "geolocation": {"country": "Unknown", "city": "—", "isp": "Bulletproof hosting"},
        "blacklisted": True,
        "findings": [{"severity": "CRITICAL", "name": "Blacklist match", "explanation": "Mock malicious IP.", "recommendation": "Block at firewall."}],
    },
    "large_org": {
        "grade": "C",
        "score": 65,
        "summary": "Sandbox: Large organizational footprint.",
        "asn": "AS64512 Example Corp",
        "cidr_blocks": ["203.0.113.0/24", "198.51.100.0/24"],
        "hosts": [{"ip": "203.0.113.10", "ports": [80, 443], "tech": ["nginx"]}],
    },
}


FAKE_LINES = [
    "[AKILI] Sandbox mode — mock data only\n",
    "[THINK] Simulating agent reasoning…\n",
    "[PROGRESS] Now checking SSL certificate…\n",
    "[TOOL] Running simulated checks…\n",
    "[OK] Baseline checks complete\n",
    "[THINK] Synthesizing mock findings…\n",
    "[AI] Generating mock report…\n",
]


async def stream_sandbox(module: str, scenario: str = "clean_scan") -> AsyncGenerator[str, None]:
    for line in FAKE_LINES:
        yield line
        await asyncio.sleep(0.4)

    data = SCENARIOS.get(scenario, SCENARIOS["clean_scan"]).copy()
    data["scan_type"] = module
    data["sandbox"] = True
    yield f"COMPLETE:{json.dumps(data)}\n"


def get_mock_report(module: str, scenario: str = "clean_scan") -> dict:
    data = SCENARIOS.get(scenario, SCENARIOS["clean_scan"]).copy()
    data["scan_type"] = module
    data["sandbox"] = True
    data["target"] = "sandbox.example.com"
    return data
