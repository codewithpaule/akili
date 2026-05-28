import re
import httpx
from typing import List, Dict, Any
from urllib.parse import urlparse


# Technology fingerprinting patterns
TECH_PATTERNS = {
    "WordPress": [
        r'wp-content',
        r'wp-includes',
        r'wp-admin',
        r'generator" content="WordPress',
        r'wp-json',
    ],
    "Drupal": [
        r'Drupal\.settings',
        r'/sites/default/',
        r'generator" content="Drupal',
    ],
    "Joomla": [
        r'/administrator/',
        r'/components/',
        r'generator" content="Joomla',
    ],
    "React": [
        r'react',
        r'react-dom',
        r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
    ],
    "Vue.js": [
        r'vue',
        r'__VUE__',
        r'v-cloak',
    ],
    "Angular": [
        r'ng-app',
        r'angular',
        r'ng-version',
    ],
    "jQuery": [
        r'jquery',
        r'\$\.fn',
    ],
    "Bootstrap": [
        r'bootstrap',
        r'btn-',
        r'container-fluid',
    ],
    "Tailwind CSS": [
        r'tailwind',
        r'tw-',
    ],
    "Laravel": [
        r'laravel',
        r'XSRF-TOKEN',
    ],
    "Django": [
        r'csrftoken',
        r'django',
    ],
    "Flask": [
        r'flask',
    ],
    "Express": [
        r'express',
    ],
    "Nginx": [
        r'server: nginx',
        r'nginx',
    ],
    "Apache": [
        r'server: apache',
        r'apache',
    ],
    "PHP": [
        r'\.php',
        r'PHP/',
    ],
    "Node.js": [
        r'node',
        r'express',
    ],
    "Python": [
        r'python',
        r'django',
        r'flask',
    ],
    "Ruby on Rails": [
        r'rails',
        r'ruby',
    ],
    "ASP.NET": [
        r'\.aspx',
        r'asp\.net',
    ],
    "Java": [
        r'\.jsp',
        r'\.do',
        r'java',
    ],
    "core-js": [
        r'core-js',
        r'core\-js',
    ],
    "jQuery Migrate": [
        r'jquery-migrate',
        r'jquery.migrate',
    ],
    "Google Font API": [
        r'fonts.googleapis.com',
        r'fonts.gstatic.com',
    ],
    "LiteSpeed": [
        r'litespeed',
    ],
    "WooCommerce": [
        r'woocommerce',
    ],
    "Elementor": [
        r'elementor',
    ],
}


VERSION = r"(\d+(?:\.\d+){0,3})"

VERSION_PATTERNS = {
    "WordPress": [rf"WordPress\s+{VERSION}", rf"wp-(?:includes|content).*?[?&]ver={VERSION}"],
    "Drupal": [rf"Drupal\s+{VERSION}", rf"drupal.*?[?&]v={VERSION}"],
    "Joomla": [rf"Joomla!?\s+{VERSION}"],
    "jQuery": [rf"jquery(?:\.min)?\.js(?:\?ver=|[?&]v=|/|-)?{VERSION}", rf"jquery@{VERSION}"],
    "Bootstrap": [rf"bootstrap(?:\.bundle|\.min)?\.(?:js|css)(?:\?ver=|[?&]v=|/|-)?{VERSION}", rf"bootstrap@{VERSION}"],
    "Vue.js": [rf"vue(?:\.runtime|\.global|\.min)?\.js(?:\?ver=|[?&]v=|/|-)?{VERSION}", rf"vue@{VERSION}"],
    "React": [rf"react(?:\.production|\.development|\.min)?\.js(?:\?ver=|[?&]v=|/|-)?{VERSION}", rf"react@{VERSION}"],
    "Angular": [rf"angular(?:\.min)?\.js(?:\?ver=|[?&]v=|/|-)?{VERSION}", rf"ng-version=[\"']{VERSION}"],
    "Nginx": [rf"nginx/{VERSION}"],
    "Apache": [rf"Apache/{VERSION}"],
    "PHP": [rf"PHP/{VERSION}", rf"php/{VERSION}"],
    "Express": [rf"Express/{VERSION}", rf"express@{VERSION}"],
    "LiteSpeed": [rf"LiteSpeed(?:/|\s){VERSION}", rf"litespeed/{VERSION}"],
    "WooCommerce": [rf"woocommerce(?:\.min)?\.js(?:\?ver=|[?&]v=|/|-)?{VERSION}", rf"woocommerce@{VERSION}"],
    "Elementor": [rf"elementor(?:\.min)?\.js(?:\?ver=|[?&]v=|/|-)?{VERSION}", rf"elementor@{VERSION}"],
}


def _headers_get(headers: Dict[str, str], name: str) -> str:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ""


async def fetch_html(url: str) -> str:
    """Fetch HTML content from URL."""
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url, headers={"User-Agent": "AKILI-Deep-Scan/1.0"})
            return response.text
    except Exception:
        return ""


async def fetch_headers(url: str) -> Dict[str, str]:
    """Fetch HTTP headers from URL."""
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url, headers={"User-Agent": "AKILI-Deep-Scan/1.0"})
            return dict(response.headers)
    except Exception:
        return {}


def detect_technologies(html: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Detect technologies from HTML content and headers."""
    detected = []
    
    # Combine HTML and headers for analysis
    content = html.lower()
    headers_str = str(headers).lower()
    combined = content + headers_str
    
    for tech, patterns in TECH_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                # Check if already detected
                if not any(d["name"] == tech for d in detected):
                    version = detect_version(tech, html, headers)
                    # Normalize unknown versions to explicit string for UI
                    version_display = version if version else "Version hidden"
                    detected.append({
                        "name": tech,
                        "version": version_display,
                        "confidence": "high" if len(patterns) > 1 else "medium",
                    })
                break
    
    # Detect from headers specifically
    server = _headers_get(headers, "Server")
    x_powered_by = _headers_get(headers, "X-Powered-By")
    
    if server:
        if "nginx" in server.lower():
            if not any(d["name"] == "Nginx" for d in detected):
                detected.append({
                    "name": "Nginx",
                    "version": extract_version(server, rf'nginx/{VERSION}') or "Version hidden",
                    "confidence": "high",
                })
        elif "apache" in server.lower():
            if not any(d["name"] == "Apache" for d in detected):
                detected.append({
                    "name": "Apache",
                    "version": extract_version(server, rf'Apache/{VERSION}') or "Version hidden",
                    "confidence": "high",
                })
    
    if x_powered_by:
        if "php" in x_powered_by.lower():
            if not any(d["name"] == "PHP" for d in detected):
                detected.append({
                    "name": "PHP",
                    "version": extract_version(x_powered_by, rf'PHP/{VERSION}') or "Version hidden",
                    "confidence": "high",
                })
        elif "asp" in x_powered_by.lower():
            if not any(d["name"] == "ASP.NET" for d in detected):
                detected.append({
                    "name": "ASP.NET",
                    "version": None,
                    "confidence": "high",
                })
    
    return detected


def detect_version(tech: str, html: str, headers: Dict[str, str]) -> str:
    """Detect version of a specific technology."""
    if tech in VERSION_PATTERNS:
        for pattern in VERSION_PATTERNS[tech]:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)

            headers_str = str(headers)
            match = re.search(pattern, headers_str, re.IGNORECASE)
            if match:
                return match.group(1)
    
    return None


def extract_version(text: str, pattern: str) -> str:
    """Extract version from text using pattern."""
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1) if match else None


async def fingerprint_technologies(url: str) -> Dict[str, Any]:
    """Perform deep technology fingerprinting."""
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.netloc
    
    # Fetch HTML and headers
    html = await fetch_html(url)
    headers = await fetch_headers(url)
    
    # Detect technologies. Wappalyzer can occasionally spend too long or warn on
    # malformed upstream regexes, so fall back to lightweight pattern matching.
    try:
        technologies = detect_technologies(html, headers)
    except Exception:
        technologies = []
    
    # Detect from meta tags
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.IGNORECASE)
    if generator:
        gen_value = generator.group(1)
        if not any(d["name"] == gen_value.split()[0] for d in technologies):
            technologies.append({
                "name": gen_value.split()[0],
                "version": " ".join(gen_value.split()[1:]) if len(gen_value.split()) > 1 else None,
                "confidence": "high",
            })
    
    # Detect JavaScript libraries from script tags
    script_sources = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    js_libs = []
    for src in script_sources:
        src_lower = src.lower()
        if "jquery" in src_lower and not any(d["name"] == "jQuery" for d in technologies):
            version = detect_version("jQuery", src, {}) or "Version hidden"
            technologies.append({
                "name": "jQuery",
                "version": version,
                "confidence": "medium",
            })
        elif "bootstrap" in src_lower and not any(d["name"] == "Bootstrap" for d in technologies):
            version = detect_version("Bootstrap", src, {}) or "Version hidden"
            technologies.append({
                "name": "Bootstrap",
                "version": version,
                "confidence": "medium",
            })
        elif "react" in src_lower and not any(d["name"] == "React" for d in technologies):
            version = detect_version("React", src, {}) or "Version hidden"
            technologies.append({
                "name": "React",
                "version": version,
                "confidence": "medium",
            })
        elif "vue" in src_lower and not any(d["name"] == "Vue.js" for d in technologies):
            version = detect_version("Vue.js", src, {}) or "Version hidden"
            technologies.append({
                "name": "Vue.js",
                "version": version,
                "confidence": "medium",
            })
    
    return {
        "url": url,
        "hostname": hostname,
        "technologies": technologies,
        "server": _headers_get(headers, "Server"),
        "powered_by": _headers_get(headers, "X-Powered-By"),
        "total_technologies": len(technologies),
    }


def run_tech_fingerprint(url: str, context: dict) -> dict:
    """Run technology fingerprinting (synchronous wrapper)."""
    try:
        import asyncio
        loop = asyncio.get_event_loop()
    except RuntimeError:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    result = loop.run_until_complete(fingerprint_technologies(url))
    
    findings = []
    
    # Generate findings based on detected technologies
    for tech in result["technologies"]:
        name = tech["name"]
        version = tech.get("version")
        version_exposed = bool(version and version != "Version hidden")

        # Check for outdated versions (simplified)
        if version_exposed:
            if name == "WordPress" and version.startswith(("4.", "5.")):
                findings.append({
                    "severity": "HIGH",
                    "name": f"Outdated WordPress version: {version}",
                    "explanation": f"WordPress {version} may have known security vulnerabilities.",
                    "recommendation": "Update to the latest WordPress version.",
                    "cve_search": f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=wordpress+{version}"
                })
            elif name == "Nginx" and version.startswith(("1.14", "1.15", "1.16", "1.17", "1.18")):
                findings.append({
                    "severity": "MEDIUM",
                    "name": f"Potentially outdated Nginx version: {version}",
                    "explanation": f"Nginx {version} may have known security issues.",
                    "recommendation": "Consider updating to the latest stable version.",
                    "cve_search": f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=nginx+{version}"
                })
            elif name == "Apache" and version.startswith(("2.2", "2.4.29", "2.4.30", "2.4.31")):
                findings.append({
                    "severity": "HIGH",
                    "name": f"Outdated Apache version: {version}",
                    "explanation": f"Apache {version} has known security vulnerabilities.",
                    "recommendation": "Update to the latest Apache version.",
                    "cve_search": f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=apache+{version}"
                })

        # Check for technologies that need security headers
        if name in ["WordPress", "Drupal", "Joomla"] and not version_exposed:
            findings.append({
                "severity": "MEDIUM",
                "name": f"{name} detected (version unknown)",
                "explanation": f"{name} is installed but version could not be determined.",
                "recommendation": "Ensure {name} is updated to the latest version and security headers are configured.",
            })
    
    # Check for missing security headers
    if result["server"]:
        findings.append({
            "severity": "INFO",
            "name": f"Server header exposed: {result['server']}",
            "explanation": "The Server header reveals the web server software and version.",
            "recommendation": "Consider hiding the Server header to reduce information disclosure.",
        })
    
    severity = "INFO"
    if any(f["severity"] == "HIGH" for f in findings):
        severity = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in findings):
        severity = "MEDIUM"
    
    return {
        "tool": "tech_fingerprint",
        "severity": severity,
        "title": "Technology fingerprinting",
        "detail": f"{result['total_technologies']} technologies detected",
        "raw": result,
        "findings": findings,
    }
