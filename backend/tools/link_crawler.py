import re
import httpx
from typing import List, Dict, Any, Set
from urllib.parse import urljoin, urlparse
from datetime import datetime


def looks_like_missing_page(html: str) -> bool:
    text = re.sub(r"\s+", " ", (html or "").lower())
    return bool(re.search(r"\b(404|not found|page not found|does not exist|could not be found)\b", text))


# Common hidden/interesting paths to check
COMMON_HIDDEN_PATHS = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/login",
    "/dashboard",
    "/api",
    "/api/v1",
    "/api/v2",
    "/config",
    "/.env",
    "/.git",
    "/.svn",
    "/backup",
    "/backups",
    "/db",
    "/database",
    "/sql",
    "/test",
    "/testing",
    "/staging",
    "/dev",
    "/debug",
    "/console",
    "/phpmyadmin",
    "/mysql",
    "/postgres",
    "/redis",
    "/mongodb",
    "/elasticsearch",
    "/solr",
    "/jenkins",
    "/grafana",
    "/kibana",
    "/prometheus",
    "/webmin",
    "/cpanel",
    "/whm",
    "/plesk",
    "/ftp",
    "/ssh",
    "/telnet",
    "/rssh",
    "/webdav",
    "/svn",
    "/git",
    "/hg",
    "/bzr",
    "/logs",
    "/log",
    "/error_log",
    "/access_log",
    "/sitemap.xml",
    "/robots.txt",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/app.config",
    "/web.config.bak",
    "/.DS_Store",
    "/Thumbs.db",
]


async def fetch_page(url: str) -> str:
    """Fetch page content."""
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url, headers={"User-Agent": "AKILI-Deep-Scan/1.0"})
            return response.text
    except Exception:
        return ""


def extract_links(html: str, base_url: str) -> List[str]:
    """Extract all links from HTML."""
    links = []
    
    # Extract href attributes
    href_pattern = r'href=["\']([^"\']+)["\']'
    for match in re.finditer(href_pattern, html, re.IGNORECASE):
        link = match.group(1)
        # Resolve relative URLs
        absolute_link = urljoin(base_url, link)
        links.append(absolute_link)
    
    # Extract src attributes (images, scripts, etc.)
    src_pattern = r'src=["\']([^"\']+)["\']'
    for match in re.finditer(src_pattern, html, re.IGNORECASE):
        link = match.group(1)
        absolute_link = urljoin(base_url, link)
        links.append(absolute_link)
    
    # Extract action attributes (forms)
    action_pattern = r'action=["\']([^"\']+)["\']'
    for match in re.finditer(action_pattern, html, re.IGNORECASE):
        link = match.group(1)
        absolute_link = urljoin(base_url, link)
        links.append(absolute_link)
    
    return links


def filter_links(links: List[str], base_domain: str) -> List[str]:
    """Filter links to only include those from the same domain."""
    filtered = []
    seen = set()
    
    for link in links:
        try:
            parsed = urlparse(link)
            if parsed.netloc == base_domain or parsed.netloc == "":
                # Remove fragment
                clean_link = link.split("#")[0]
                if clean_link and clean_link not in seen:
                    seen.add(clean_link)
                    filtered.append(clean_link)
        except Exception:
            pass
    
    return filtered


async def check_path_exists(base_url: str, path: str) -> Dict[str, Any]:
    """Check if a specific path exists and returns status."""
    url = urljoin(base_url, path)
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            response = await client.get(url, headers={"User-Agent": "AKILI-Deep-Scan/1.0"})
            
            missing_body = looks_like_missing_page(response.text[:10000])
            return {
                "path": path,
                "url": url,
                "status_code": response.status_code,
                "exists": response.status_code < 400 and not missing_body,
                "content_length": len(response.content),
                "content_type": response.headers.get("Content-Type", ""),
                "missing_body": missing_body,
            }
    except Exception:
        return {
            "path": path,
            "url": url,
            "status_code": None,
            "exists": False,
            "content_length": 0,
            "content_type": "",
        }


async def discover_hidden_paths(base_url: str) -> List[Dict[str, Any]]:
    """Discover hidden paths by checking common paths."""
    results = []
    
    # Check common hidden paths
    tasks = [check_path_exists(base_url, path) for path in COMMON_HIDDEN_PATHS]
    path_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in path_results:
        if isinstance(result, Exception):
            continue
        if result["exists"]:
            results.append(result)
    
    return results


async def ai_discover_hidden_paths(base_url: str, html_content: str) -> List[str]:
    """Use AI to discover potential hidden paths from HTML content."""
    try:
        from groq import Groq
        import os
        
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            return []
        
        client = Groq(api_key=api_key)
        
        prompt = f"""Analyze this HTML content and identify potential hidden paths, endpoints, or sensitive directories that might exist on the website. 
Look for patterns like:
- API endpoints mentioned in JavaScript
- Admin or management paths
- Configuration or backup paths
- Test or staging endpoints
- Any other interesting paths

Base URL: {base_url}

HTML Content (first 5000 chars):
{html_content[:5000]}

Return ONLY a JSON array of paths (e.g., ["/api/v1/users", "/admin/dashboard", "/config.json"]). Do not include explanations."""

        response = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=500
        )
        
        content = response.choices[0].message.content.strip()
        
        # Parse JSON response
        import json
        paths = json.loads(content)
        
        if isinstance(paths, list):
            return paths
        
        return []
    except Exception:
        return []


async def crawl_website(url: str, max_depth: int = 2, max_pages: int = 50) -> Dict[str, Any]:
    """Crawl website to discover all links and hidden paths."""
    parsed = urlparse(url)
    base_domain = parsed.netloc
    base_url = f"{parsed.scheme}://{base_domain}"
    
    visited: Set[str] = set()
    to_visit: List[str] = [url]
    all_links: List[str] = []
    discovered_paths: List[Dict[str, Any]] = []
    
    depth = 0
    
    while to_visit and depth < max_depth and len(visited) < max_pages:
        current_batch = to_visit[:10]  # Process in batches
        to_visit = to_visit[10:]
        
        # Fetch pages in batch
        fetch_tasks = [fetch_page(link) for link in current_batch]
        pages = await asyncio.gather(*fetch_tasks, return_exceptions=True)
        
        for page_url, page_content in zip(current_batch, pages):
            if page_url in visited or isinstance(page_content, Exception):
                continue
            
            visited.add(page_url)
            
            if page_content:
                # Extract links
                links = extract_links(page_content, page_url)
                filtered_links = filter_links(links, base_domain)
                
                for link in filtered_links:
                    if link not in visited and link not in to_visit:
                        to_visit.append(link)
                    if link not in all_links:
                        all_links.append(link)
        
        depth += 1
    
    # Discover hidden paths using common paths
    hidden_paths = await discover_hidden_paths(base_url)
    
    # If few hidden paths found, use AI to discover more
    if len(hidden_paths) < 3:
        try:
            # Fetch homepage content for AI analysis
            homepage_content = await fetch_page(url)
            if homepage_content:
                ai_paths = await ai_discover_hidden_paths(base_url, homepage_content)
                
                # Check AI-discovered paths
                ai_path_tasks = [check_path_exists(base_url, path) for path in ai_paths[:20]]
                ai_path_results = await asyncio.gather(*ai_path_tasks, return_exceptions=True)
                
                for result in ai_path_results:
                    if isinstance(result, Exception):
                        continue
                    if result["exists"] and result not in hidden_paths:
                        hidden_paths.append(result)
        except Exception:
            pass
    
    # Categorize links
    internal_links = [link for link in all_links if base_domain in link]
    external_links = [link for link in all_links if base_domain not in link]
    
    # Identify interesting links
    interesting_links = []
    for link in internal_links:
        if any(keyword in link.lower() for keyword in ["admin", "login", "api", "config", "backup", "debug", "test"]):
            interesting_links.append(link)
    
    return {
        "base_url": base_url,
        "total_links_found": len(all_links),
        "internal_links": len(internal_links),
        "external_links": len(external_links),
        "pages_crawled": len(visited),
        "interesting_links": interesting_links,
        "hidden_paths": hidden_paths,
        "all_links": all_links[:100],  # Limit to 100
        "crawl_timestamp": datetime.utcnow().isoformat()
    }


def run_link_crawler(url: str, context: dict) -> dict:
    """Run link crawler (synchronous wrapper)."""
    try:
        import asyncio
        loop = asyncio.get_event_loop()
    except RuntimeError:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    result = loop.run_until_complete(crawl_website(url))
    
    findings = []
    
    # Generate findings based on discovered paths
    for path_info in result["hidden_paths"]:
        path = path_info["path"]
        status_code = path_info["status_code"]
        
        # Check for sensitive paths
        if any(keyword in path.lower() for keyword in ["admin", "login", "dashboard", "config"]):
            if status_code == 200:
                findings.append({
                    "severity": "HIGH",
                    "name": f"Sensitive path exposed: {path}",
                    "explanation": f"The path {path} is publicly accessible (HTTP {status_code}).",
                    "recommendation": "Restrict access to this path or ensure proper authentication is enforced.",
                    "url": path_info["url"]
                })
            elif status_code in [401, 403]:
                findings.append({
                    "severity": "INFO",
                    "name": f"Sensitive path protected: {path}",
                    "explanation": f"The path {path} exists but is protected (HTTP {status_code}).",
                    "recommendation": "Ensure the protection is properly configured.",
                    "url": path_info["url"]
                })
        
        # Check for backup/config files
        if any(keyword in path.lower() for keyword in ["backup", "config", ".env", ".git", ".svn"]):
            if status_code == 200:
                findings.append({
                    "severity": "CRITICAL",
                    "name": f"Backup/config file exposed: {path}",
                    "explanation": f"The file {path} is publicly accessible (HTTP {status_code}). This may contain sensitive information.",
                    "recommendation": "Remove this file from public access or restrict it immediately.",
                    "url": path_info["url"]
                })
        
        # Check for admin panels
        if "admin" in path.lower() and status_code == 200:
            findings.append({
                "severity": "MEDIUM",
                "name": f"Admin panel accessible: {path}",
                "explanation": f"An admin panel is accessible at {path}. Ensure it's properly secured.",
                "recommendation": "Review access controls and implement strong authentication.",
                "url": path_info["url"]
            })
    
    # Check for interesting links
    for link in result["interesting_links"]:
        if "api" in link.lower():
            findings.append({
                "severity": "INFO",
                "name": f"API endpoint discovered: {link}",
                "explanation": "An API endpoint was discovered during crawling.",
                "recommendation": "Review API security and ensure proper authentication.",
                "url": link
            })
    
    # If many hidden paths found, flag as potential issue
    if len(result["hidden_paths"]) > 5:
        findings.append({
            "severity": "MEDIUM",
            "name": "Multiple hidden paths discovered",
            "explanation": f"{len(result['hidden_paths'])} potentially sensitive paths were discovered.",
            "recommendation": "Review these paths and ensure they are properly secured or removed."
        })
    
    severity = "INFO"
    if any(f["severity"] == "CRITICAL" for f in findings):
        severity = "CRITICAL"
    elif any(f["severity"] == "HIGH" for f in findings):
        severity = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in findings):
        severity = "MEDIUM"
    
    return {
        "tool": "link_crawler",
        "severity": severity,
        "title": "Link crawler and hidden path discovery",
        "detail": f"{result['total_links_found']} links found, {len(result['hidden_paths'])} hidden paths",
        "raw": result,
        "findings": findings,
    }
