import httpx
from typing import List, Dict, Any
from datetime import datetime


# Known vulnerable technology versions (simplified database)
KNOWN_VULNERABILITIES = {
    "WordPress": {
        "4.0.0": {"cve": "CVE-2014-0166", "severity": "CRITICAL", "description": "SQL injection vulnerability"},
        "4.1.0": {"cve": "CVE-2014-0166", "severity": "CRITICAL", "description": "SQL injection vulnerability"},
        "4.2.0": {"cve": "CVE-2015-3429", "severity": "CRITICAL", "description": "Cross-site scripting vulnerability"},
        "4.3.0": {"cve": "CVE-2015-3429", "severity": "CRITICAL", "description": "Cross-site scripting vulnerability"},
        "4.4.0": {"cve": "CVE-2015-5714", "severity": "HIGH", "description": "Privilege escalation"},
        "4.5.0": {"cve": "CVE-2015-5714", "severity": "HIGH", "description": "Privilege escalation"},
        "4.6.0": {"cve": "CVE-2016-6897", "severity": "HIGH", "description": "Path traversal"},
        "4.7.0": {"cve": "CVE-2017-6897", "severity": "HIGH", "description": "Cross-site scripting"},
        "4.8.0": {"cve": "CVE-2018-6389", "severity": "MEDIUM", "description": "Denial of service"},
        "4.9.0": {"cve": "CVE-2019-6977", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "5.0.0": {"cve": "CVE-2020-28028", "severity": "HIGH", "description": "Authentication bypass"},
        "5.1.0": {"cve": "CVE-2021-24347", "severity": "HIGH", "description": "SQL injection"},
        "5.2.0": {"cve": "CVE-2021-39216", "severity": "HIGH", "description": "Cross-site scripting"},
        "5.3.0": {"cve": "CVE-2021-39216", "severity": "HIGH", "description": "Cross-site scripting"},
        "5.4.0": {"cve": "CVE-2021-39216", "severity": "HIGH", "description": "Cross-site scripting"},
        "5.5.0": {"cve": "CVE-2021-39216", "severity": "HIGH", "description": "Cross-site scripting"},
        "5.6.0": {"cve": "CVE-2021-39216", "severity": "HIGH", "description": "Cross-site scripting"},
        "5.7.0": {"cve": "CVE-2021-39216", "severity": "HIGH", "description": "Cross-site scripting"},
        "5.8.0": {"cve": "CVE-2021-39216", "severity": "HIGH", "description": "Cross-site scripting"},
        "5.9.0": {"cve": "CVE-2021-39216", "severity": "HIGH", "description": "Cross-site scripting"},
    },
    "Nginx": {
        "1.14.0": {"cve": "CVE-2019-20372", "severity": "MEDIUM", "description": "Memory leak"},
        "1.15.0": {"cve": "CVE-2019-20372", "severity": "MEDIUM", "description": "Memory leak"},
        "1.16.0": {"cve": "CVE-2019-20372", "severity": "MEDIUM", "description": "Memory leak"},
        "1.17.0": {"cve": "CVE-2019-20372", "severity": "MEDIUM", "description": "Memory leak"},
        "1.18.0": {"cve": "CVE-2021-23017", "severity": "HIGH", "description": "Memory corruption"},
    },
    "Apache": {
        "2.2.0": {"cve": "CVE-2017-15710", "severity": "CRITICAL", "description": "Denial of service"},
        "2.4.29": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.30": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.31": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.32": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.33": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.34": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.35": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.36": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.37": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.38": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.39": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.40": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.41": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.42": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.43": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.44": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.45": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.46": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.47": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.48": {"cve": "CVE-2017-15715", "severity": "HIGH", "description": "Path traversal"},
        "2.4.49": {"cve": "CVE-2021-41773", "severity": "CRITICAL", "description": "Path traversal"},
        "2.4.50": {"cve": "CVE-2021-44790", "severity": "CRITICAL", "description": "Memory corruption"},
    },
    "PHP": {
        "5.6.0": {"cve": "CVE-2016-7124", "severity": "HIGH", "description": "Session deserialization"},
        "7.0.0": {"cve": "CVE-2016-7124", "severity": "HIGH", "description": "Session deserialization"},
        "7.1.0": {"cve": "CVE-2016-7124", "severity": "HIGH", "description": "Session deserialization"},
        "7.2.0": {"cve": "CVE-2016-7124", "severity": "HIGH", "description": "Session deserialization"},
        "7.3.0": {"cve": "CVE-2019-11043", "severity": "HIGH", "description": "Buffer overflow"},
        "7.4.0": {"cve": "CVE-2019-11043", "severity": "HIGH", "description": "Buffer overflow"},
    },
    "jQuery": {
        "1.0.0": {"cve": "CVE-2011-4969", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "1.6.0": {"cve": "CVE-2011-4969", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "1.7.0": {"cve": "CVE-2012-6708", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "1.8.0": {"cve": "CVE-2012-6708", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "1.9.0": {"cve": "CVE-2012-6708", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "1.10.0": {"cve": "CVE-2012-6708", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "1.11.0": {"cve": "CVE-2012-6708", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "1.12.0": {"cve": "CVE-2012-6708", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "2.0.0": {"cve": "CVE-2012-6708", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "2.1.0": {"cve": "CVE-2012-6708", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "2.2.0": {"cve": "CVE-2012-6708", "severity": "MEDIUM", "description": "Cross-site scripting"},
        "3.0.0": {"cve": "CVE-2020-11022", "severity": "HIGH", "description": "Cross-site scripting"},
        "3.1.0": {"cve": "CVE-2020-11022", "severity": "HIGH", "description": "Cross-site scripting"},
        "3.2.0": {"cve": "CVE-2020-11022", "severity": "HIGH", "description": "Cross-site scripting"},
        "3.3.0": {"cve": "CVE-2020-11022", "severity": "HIGH", "description": "Cross-site scripting"},
        "3.4.0": {"cve": "CVE-2020-11022", "severity": "HIGH", "description": "Cross-site scripting"},
        "3.5.0": {"cve": "CVE-2020-11022", "severity": "HIGH", "description": "Cross-site scripting"},
    },
}


async def search_cve_api(query: str) -> List[Dict[str, Any]]:
    """Search CVE database via NVD API."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # NVD API v2.0
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
            response = await client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                for item in data.get("vulnerabilities", [])[:10]:  # Limit to 10 results
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")
                    descriptions = cve.get("descriptions", [])
                    description = descriptions[0].get("value", "") if descriptions else ""
                    
                    # Get severity
                    metrics = cve.get("metrics", {})
                    cvss_score = None
                    severity = "UNKNOWN"
                    
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                    
                    cves.append({
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
                
                return cves
    except Exception:
        pass
    
    return []


def check_known_vulnerabilities(technology: str, version: str) -> List[Dict[str, Any]]:
    """Check against known vulnerability database."""
    vulnerabilities = []
    
    if technology in KNOWN_VULNERABILITIES:
        tech_vulns = KNOWN_VULNERABILITIES[technology]
        
        # Exact version match
        if version in tech_vulns:
            vuln = tech_vulns[version]
            vulnerabilities.append({
                "cve_id": vuln["cve"],
                "severity": vuln["severity"],
                "description": vuln["description"],
                "version": version,
                "link": f"https://nvd.nist.gov/vuln/detail/{vuln['cve']}"
            })
        else:
            # Check for older versions (simplified logic)
            try:
                major_minor = ".".join(version.split(".")[:2])
                for known_version, vuln in tech_vulns.items():
                    if known_version.startswith(major_minor):
                        vulnerabilities.append({
                            "cve_id": vuln["cve"],
                            "severity": vuln["severity"],
                            "description": vuln["description"],
                            "version": version,
                            "link": f"https://nvd.nist.gov/vuln/detail/{vuln['cve']}"
                        })
                        break
            except Exception:
                pass
    
    return vulnerabilities


async def lookup_cves(technologies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Lookup CVEs for detected technologies."""
    results = {
        "total_technologies": len(technologies),
        "vulnerabilities_found": 0,
        "vulnerabilities": [],
        "technology_details": []
    }
    
    for tech in technologies:
        name = tech["name"]
        version = tech.get("version")
        
        # Check known vulnerabilities
        known_vulns = check_known_vulnerabilities(name, version) if version else []
        
        # If no known vulnerabilities or version unknown, try API search
        if not known_vulns:
            query = f"{name}"
            if version:
                query += f" {version}"
            
            api_results = await search_cve_api(query)
            
            tech_details = {
                "name": name,
                "version": version,
                "known_vulnerabilities": known_vulns,
                "api_search_results": api_results,
                "total_vulnerabilities": len(known_vulns) + len(api_results)
            }
            
            results["vulnerabilities"].extend(known_vulns)
            results["vulnerabilities"].extend(api_results)
        else:
            tech_details = {
                "name": name,
                "version": version,
                "known_vulnerabilities": known_vulns,
                "api_search_results": [],
                "total_vulnerabilities": len(known_vulns)
            }
            
            results["vulnerabilities"].extend(known_vulns)
        
        results["technology_details"].append(tech_details)
        results["vulnerabilities_found"] += tech_details["total_vulnerabilities"]
    
    return results


async def run_cve_lookup(technologies: list, context: dict) -> dict:
    """Run CVE lookup (async-safe wrapper)."""
    result = await lookup_cves(technologies)
    
    findings = []
    
    # Generate findings based on vulnerabilities
    for vuln in result["vulnerabilities"]:
        severity = vuln.get("severity", "UNKNOWN")
        cve_id = vuln.get("cve_id", "")
        description = vuln.get("description", "")
        link = vuln.get("link", "")
        
        if severity == "CRITICAL":
            findings.append({
                "severity": "CRITICAL",
                "name": f"Critical vulnerability: {cve_id}",
                "explanation": description,
                "recommendation": "Update to the latest secure version immediately.",
                "external_link": link
            })
        elif severity == "HIGH":
            findings.append({
                "severity": "HIGH",
                "name": f"High severity vulnerability: {cve_id}",
                "explanation": description,
                "recommendation": "Update to the latest secure version as soon as possible.",
                "external_link": link
            })
        elif severity == "MEDIUM":
            findings.append({
                "severity": "MEDIUM",
                "name": f"Medium severity vulnerability: {cve_id}",
                "explanation": description,
                "recommendation": "Consider updating to the latest version.",
                "external_link": link
            })
        elif severity == "LOW":
            findings.append({
                "severity": "LOW",
                "name": f"Low severity vulnerability: {cve_id}",
                "explanation": description,
                "recommendation": "Update when convenient.",
                "external_link": link
            })
    
    # If no vulnerabilities found
    if result["vulnerabilities_found"] == 0:
        findings.append({
            "severity": "INFO",
            "name": "No known vulnerabilities detected",
            "explanation": "No known CVEs were found for the detected technologies.",
            "recommendation": "Continue to monitor for new vulnerabilities and keep systems updated."
        })
    
    severity = "INFO"
    if any(f["severity"] == "CRITICAL" for f in findings):
        severity = "CRITICAL"
    elif any(f["severity"] == "HIGH" for f in findings):
        severity = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in findings):
        severity = "MEDIUM"
    
    return {
        "tool": "cve_lookup",
        "severity": severity,
        "title": "CVE vulnerability lookup",
        "detail": f"{result['vulnerabilities_found']} vulnerabilities found",
        "raw": result,
        "findings": findings,
    }
