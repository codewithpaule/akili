"""Human-readable, scan-type-aware message templates for the agent terminal."""

from typing import Literal

ScanModule = Literal[
    "website", "vulnerability", "subdomains", "ip",
    "organization", "person", "company", "email", "domain", "api"
]

MODULE_NAMES = {
    "website":       "website security scan",
    "vulnerability": "vulnerability assessment",
    "subdomains":    "subdomain discovery",
    "ip":            "IP address investigation",
    "organization":  "organisation footprint analysis",
    "person":        "person search",
    "company":       "company intelligence scan",
    "email":         "email investigation",
    "domain":        "domain reputation check",
    "api":           "API surface scan",
}

START_MESSAGES = {
    "website":       "Starting security assessment for {target}",
    "vulnerability": "Starting vulnerability assessment for {target}",
    "subdomains":    "Searching for subdomains of {target}",
    "ip":            "Looking up intelligence on IP address {target}",
    "organization":  "Mapping the public footprint of {target}",
    "person":        "Searching public records for {target}",
    "company":       "Gathering public intelligence on {target}",
    "email":         "Investigating email address {target}",
    "domain":        "Checking reputation and records for {target}",
    "api":           "Scanning the API surface at {target}",
}

PLANNING_MESSAGES = {
    "website":       "Deciding which security checks will reveal the most about this site",
    "vulnerability": "Planning which vulnerability checks apply to this target",
    "subdomains":    "Figuring out the best way to map subdomains for this domain",
    "ip":            "Planning the IP investigation, checking geolocation, ports, and hosted services",
    "organization":  "Planning the organisation footprint scan",
    "person":        "Working out which platforms and sources are most likely to have information about this person",
    "company":       "Planning the company intelligence scan",
    "email":         "Checking what can be found about this email address",
    "domain":        "Planning the domain reputation and DNS investigation",
    "api":           "Planning the API surface scan",
}

THINKING_MESSAGES = {
    "website":       "Reading the findings so far and deciding what to check next",
    "vulnerability": "Reviewing vulnerabilities found so far",
    "subdomains":    "Processing subdomain results",
    "ip":            "Analysing what this IP address is running",
    "organization":  "Reviewing the organisation's public footprint",
    "person":        "Reviewing what has been found so far about this person",
    "company":       "Reviewing the company intelligence gathered so far",
    "email":         "Analysing the email investigation results",
    "domain":        "Reviewing domain reputation data",
    "api":           "Reviewing the API surface findings",
}

WRAPPING_UP = {
    "website":       "All security checks complete, writing the report",
    "vulnerability": "Vulnerability assessment complete, writing the report",
    "subdomains":    "Subdomain discovery complete, writing the report",
    "ip":            "IP investigation complete, writing the report",
    "organization":  "Organisation scan complete, writing the report",
    "person":        "Search complete, building your person report",
    "company":       "Company intelligence scan complete, writing the report",
    "email":         "Email investigation complete, writing the report",
    "domain":        "Domain check complete, writing the report",
    "api":           "API scan complete, writing the report",
}

TOOL_RUNNING = {
    "website":  "Checking {tool}",
    "ip":       "Running {tool} on this IP address",
    "person":   "Searching {tool} for public information",
    "email":    "Checking {tool} for this email address",
    "domain":   "Running {tool} for this domain",
    "_default": "Running {tool}",
}

FOUND_MESSAGES = {
    "website":  "Found something worth noting",
    "ip":       "Found a relevant detail",
    "person":   "Found a public record",
    "email":    "Found relevant email data",
    "domain":   "Found relevant domain data",
    "_default": "Check complete",
}

CLEAN_MESSAGES = {
    "website":  "This check came back clean",
    "ip":       "Nothing concerning found here",
    "person":   "Nothing found at this source",
    "email":    "Nothing found here",
    "domain":   "Nothing notable found",
    "_default": "Check complete",
}

REPORT_WRITING = {
    "website":       "Writing your security report",
    "vulnerability": "Writing your vulnerability report",
    "subdomains":    "Compiling subdomain results",
    "ip":            "Writing your IP intelligence report",
    "organization":  "Writing your organisation report",
    "person":        "Pulling together everything found about this person",
    "company":       "Writing your company intelligence report",
    "email":         "Writing your email investigation report",
    "domain":        "Writing your domain reputation report",
    "api":           "Writing your API security report",
}

PERSON_MESSAGES = {
    "checking_profile":  "Looking for a public profile at {url}",
    "profile_found":     "Found a {platform} profile, verifying it is the right person",
    "profile_confirmed": "Confirmed {platform} profile belongs to {name}",
    "profile_rejected":  "That {platform} profile is a different person, skipping it",
    "image_search":      "Searching for photos of {name}",
    "breach_check":      "Checking if this person appears in any public breach records",
    "summarising":       "Building a summary of what was found about {name}",
    "no_match":          "Could not verify a profile with enough confidence, report will include what was found",
}

IP_MESSAGES = {
    "geo":        "Looking up where this IP address is located",
    "ports":      "Checking which ports and services are open on this IP",
    "reverse":    "Checking what domains are pointing to this IP address",
    "asn":        "Looking up the network operator for this IP",
    "reputation": "Checking if this IP has a negative reputation",
}

WEBSITE_MESSAGES = {
    "ssl":         "Checking the SSL certificate",
    "headers":     "Reading the HTTP security headers",
    "fingerprint":   "Identifying the technology stack",
    "whois":       "Looking up domain registration records",
    "ports":       "Checking for open ports",
    "cve":         "Looking for known vulnerabilities in the detected software",
    "exposed":     "Checking for exposed files and sensitive paths",
    "crawl":       "Crawling internal links to map the site structure",
}


def get(key: str, module: str, **kwargs) -> str:
    """Get a message for a given key and module, with optional format vars."""
    tables = {
        "start":        START_MESSAGES,
        "planning":     PLANNING_MESSAGES,
        "thinking":     THINKING_MESSAGES,
        "wrapping_up":  WRAPPING_UP,
        "report":       REPORT_WRITING,
        "found":        FOUND_MESSAGES,
        "clean":        CLEAN_MESSAGES,
        "tool_running": TOOL_RUNNING,
    }
    table = tables.get(key, {})
    msg = table.get(module) or table.get("_default") or ""
    if kwargs:
        try:
            msg = msg.format(**kwargs)
        except (KeyError, ValueError):
            pass
    return msg
