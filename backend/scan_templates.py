"""Multi-module scan templates."""

import json
import uuid
from typing import Generator

from agent import run_agent, stream_line

TEMPLATES = {
    "pre_launch": {
        "modules": ["website", "vulnerability", "subdomains"],
        "label": "Pre-Launch Checklist",
    },
    "freelancer": {
        "modules": ["person", "company", "domain", "email"],
        "label": "Freelancer Due Diligence",
    },
    "monthly_audit": {
        "modules": ["website", "vulnerability"],
        "label": "Monthly Security Audit",
    },
    "vendor": {
        "modules": ["company", "domain", "organization", "website"],
        "label": "Vendor Assessment",
    },
    "full": {
        "modules": ["website", "vulnerability", "subdomains", "person", "company", "email", "domain"],
        "label": "Full Investigation",
    },
}


def run_template(template_id: str, target: str, scan_id: str, *, user_id: str = "") -> Generator[str, None, None]:
    tpl = TEMPLATES.get(template_id)
    if not tpl:
        yield stream_line("AKILI", "Unknown template")
        yield f"COMPLETE:{json.dumps({'error': 'unknown template'})}\n"
        return

    yield stream_line("AKILI", f"Running template: {tpl['label']}")
    combined = {"template": template_id, "modules_run": [], "findings": [], "reports": []}

    total = len(tpl["modules"])
    for idx, mod in enumerate(tpl["modules"], 1):
        yield stream_line("AKILI", f"Template step {idx}/{total}: {mod}")
        sub_id = str(uuid.uuid4())
        for chunk in run_agent(mod, target, sub_id, lite=True):
            if chunk.startswith("COMPLETE:"):
                try:
                    rep = json.loads(chunk.replace("COMPLETE:", ""))
                    combined["reports"].append({"module": mod, "report": rep})
                    combined["findings"].extend(rep.get("findings", []))
                except json.JSONDecodeError:
                    pass
            else:
                yield chunk
        combined["modules_run"].append(mod)

    combined["grade"] = "B"
    combined["score"] = 70
    combined["summary"] = f"Combined report from {len(tpl['modules'])} modules."
    combined["scan_type"] = "template"

    from database import save_scan

    save_scan(scan_id, "template", target, combined, len(tpl["modules"]), user_id=user_id)
    yield stream_line("DONE", "Template scan complete")
    yield f"COMPLETE:{json.dumps(combined)}\n"
