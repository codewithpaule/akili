import re
import uuid
from urllib.parse import urlparse

import httpx
from tools.async_util import run_async
from tools.fallbacks import get_cvss_severity, lookup_cves_with_fallback

WAPPALYZER_AVAILABLE = False
try:
    from Wappalyzer import Wappalyzer, WebPage

    WAPPALYZER_AVAILABLE = True
except Exception:
    pass

HTML_HINTS = [
    (r"wp-content|wp-includes", "WordPress", ["CMS"]),
    (r"/wp-json/", "WordPress", ["CMS"]),
    (r"drupal\.js|Drupal\.settings", "Drupal", ["CMS"]),
    (r"cdn\.shopify\.com", "Shopify", ["E-commerce"]),
    (r"react(?:\.production)?\.min\.js|__NEXT_DATA__|_next/static", "React", ["JavaScript framework"]),
    (r"vue(?:\.runtime)?(?:\.global)?|vue\.js", "Vue.js", ["JavaScript framework"]),
    (r"angular(?:\.min)?\.js|ng-version", "Angular", ["JavaScript framework"]),
    (r"jquery(?:\.min)?\.js", "jQuery", ["JavaScript library"]),
    (r"bootstrap(?:\.min)?\.(?:js|css)", "Bootstrap", ["UI framework"]),
    (r"cdn\.cloudflare\.com|cf-ray", "Cloudflare", ["CDN"]),
    (r"google-analytics\.com|gtag\(", "Google Analytics", ["Analytics"]),
    (r"googletagmanager\.com", "Google Tag Manager", ["Tag manager"]),
    (r"laravel|livewire", "Laravel", ["Framework"]),
    (r"django", "Django", ["Framework"]),
    (r"next\.js|__NEXT_DATA__", "Next.js", ["JavaScript framework"]),
    (r"elementor", "Elementor", ["Page builder"]),
    (r"woocommerce", "WooCommerce", ["E-commerce"]),
    (r"phpmyadmin", "phpMyAdmin", ["Database tool"]),
    (r"moodle", "Moodle", ["LMS"]),
]

# (regex on HTML/assets, display name, categories)
ASSET_VERSION_PATTERNS = [
    (r"jquery[.-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", "jQuery", ["JavaScript library"]),
    (r"bootstrap[.-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)", "Bootstrap", ["UI framework"]),
    (r"react(?:\.dom)?[.-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", "React", ["JavaScript framework"]),
    (r"vue[.-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", "Vue.js", ["JavaScript framework"]),
    (r"angular[.-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", "Angular", ["JavaScript framework"]),
    (r"wp-embed\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)", "WordPress", ["CMS"]),
    (r"wp-includes/.+\?ver=(\d+\.\d+(?:\.\d+)?)", "WordPress", ["CMS"]),
    (r"/plugins/elementor/.+\?ver=(\d+\.\d+(?:\.\d+)?)", "Elementor", ["Page builder"]),
    (r"woocommerce/.+\?ver=(\d+\.\d+(?:\.\d+)?)", "WooCommerce", ["E-commerce"]),
    (r"drupal\.js\?v=(\d+\.\d+(?:\.\d+)?)", "Drupal", ["CMS"]),
    (r"lodash[.-]?(\d+\.\d+(?:\.\d+)?)", "Lodash", ["JavaScript library"]),
    (r"moment[.-]?(\d+\.\d+(?:\.\d+)?)", "Moment.js", ["JavaScript library"]),
    (r"font-awesome/(\d+\.\d+(?:\.\d+)?)", "Font Awesome", ["Font scripts"]),
    (r"tinymce/(\d+\.\d+(?:\.\d+)?)", "TinyMCE", ["Rich text editor"]),
]

EXTRA_HEADERS = (
    ("server", "Web server"),
    ("x-powered-by", "Framework"),
    ("x-aspnet-version", "ASP.NET"),
    ("x-aspnetmvc-version", "ASP.NET MVC"),
    ("x-generator", "Generator"),
    ("x-drupal-cache", "Drupal"),
    ("x-varnish", "Varnish"),
    ("via", "Proxy"),
)


def _extract_domain(url: str) -> str:
    return urlparse(url).hostname or url


def _tech_entry(name: str, categories: list | None = None, version: str | None = None, confidence: int = 80) -> dict:
    return {
        "name": name,
        "categories": categories or [],
        "version": version,
        "confidence": confidence,
        "cves": [],
        "cve_count": 0,
        "cve_severity": "none",
        "cve_source": "none",
    }


def _parse_banner(value: str, default_category: str) -> dict | None:
    if not value or not value.strip():
        return None
    value = value.strip()
    name = value.split("/")[0].strip() or value
    version = value.split("/", 1)[1].strip() if "/" in value else None
    return _tech_entry(name, [default_category], version)


def _tech_index(technologies: list[dict]) -> dict[str, dict]:
    return {t["name"].lower(): t for t in technologies}


def _upsert_tech(technologies: list[dict], seen: set[str], entry: dict) -> None:
    key = entry["name"].lower()
    idx = _tech_index(technologies)
    if key in idx:
        existing = idx[key]
        if entry.get("version") and not existing.get("version"):
            existing["version"] = entry["version"]
        if entry.get("categories") and not existing.get("categories"):
            existing["categories"] = entry["categories"]
        return
    if key not in seen:
        seen.add(key)
        technologies.append(entry)


def _merge_wappalyzer(technologies: list[dict], extra: list[dict]) -> None:
    idx = _tech_index(technologies)
    for tech in extra:
        key = tech["name"].lower()
        if key in idx:
            if tech.get("version") and not idx[key].get("version"):
                idx[key]["version"] = tech["version"]
            if tech.get("categories"):
                merged = list(dict.fromkeys((idx[key].get("categories") or []) + tech["categories"]))
                idx[key]["categories"] = merged
            if tech.get("confidence", 0) > idx[key].get("confidence", 0):
                idx[key]["confidence"] = tech["confidence"]
        else:
            technologies.append(tech)


def _scan_plugin_versions(html: str, technologies: list[dict], seen: set[str]) -> None:
    """WordPress/CMS plugins and themes from ?ver= in asset URLs."""
    for m in re.finditer(
        r"/(?:wp-content|wp-includes)/(?:plugins|themes)/([^/]+)/[^\"']*\?ver=([\d.]+)",
        html,
        re.I,
    ):
        slug = m.group(1).replace("-", " ").replace("_", " ").title()
        _upsert_tech(technologies, seen, _tech_entry(slug, ["Plugin"], m.group(2), 88))
    for m in re.finditer(r'href=["\']([^"\']+\.css)\?ver=([\d.]+)', html, re.I):
        base = m.group(1).split("/")[-1].replace(".min.css", "").replace(".css", "")
        if len(base) > 2:
            name = base.replace("-", " ").title()
            _upsert_tech(technologies, seen, _tech_entry(name, ["Stylesheet"], m.group(2), 75))


def _scan_script_libraries(html: str, technologies: list[dict], seen: set[str]) -> None:
    """Detect libraries from script src path names."""
    lib_map = {
        "swiper": ("Swiper", ["UI"]),
        "popper": ("Popper.js", ["JavaScript library"]),
        "select2": ("Select2", ["UI"]),
        "datatables": ("DataTables", ["JavaScript library"]),
        "chart.js": ("Chart.js", ["JavaScript library"]),
        "fullcalendar": ("FullCalendar", ["JavaScript library"]),
        "owl.carousel": ("Owl Carousel", ["UI"]),
        "slick": ("Slick", ["UI"]),
        "aos": ("AOS", ["Animation"]),
        "gsap": ("GSAP", ["Animation"]),
        "three": ("Three.js", ["JavaScript library"]),
        "pdf.js": ("PDF.js", ["JavaScript library"]),
        "recaptcha": ("reCAPTCHA", ["Security"]),
        "grecaptcha": ("reCAPTCHA", ["Security"]),
        "microsoft": ("Microsoft ASP.NET", ["Framework"]),
        "aspnet": ("ASP.NET", ["Framework"]),
        "blazor": ("Blazor", ["Framework"]),
    }
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        src = m.group(1).lower()
        for key, (name, cats) in lib_map.items():
            if key in src:
                ver = None
                vm = re.search(r"[\./-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", src)
                if vm:
                    ver = vm.group(1)
                _upsert_tech(technologies, seen, _tech_entry(name, cats, ver))
                break


def _scan_html_assets(html: str, technologies: list[dict], seen: set[str]) -> None:
    for pattern, name, cats in ASSET_VERSION_PATTERNS:
        for m in re.finditer(pattern, html, re.I):
            ver = m.group(1)
            _upsert_tech(technologies, seen, _tech_entry(name, cats, ver, 85))

    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        src = m.group(1)
        for pattern, name, cats in ASSET_VERSION_PATTERNS:
            sm = re.search(pattern, src, re.I)
            if sm:
                _upsert_tech(technologies, seen, _tech_entry(name, cats, sm.group(1), 82))
                break

    for m in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\']', html, re.I):
        href = m.group(1)
        for pattern, name, cats in ASSET_VERSION_PATTERNS:
            sm = re.search(pattern, href, re.I)
            if sm:
                _upsert_tech(technologies, seen, _tech_entry(name, cats, sm.group(1), 80))
                break


async def _enrich_cves(technologies: list[dict]) -> tuple[list[dict], str]:
    cve_source_default = "none"
    for tech in technologies:
        if not tech.get("version"):
            continue
        cves, source = await lookup_cves_with_fallback(tech["name"], tech["version"])
        tech["cves"] = cves
        tech["cve_count"] = len(cves)
        tech["cve_source"] = source
        if source != "none":
            cve_source_default = source
        if any(c.get("cvss", 0) >= 9.0 for c in cves):
            tech["cve_severity"] = "critical"
        elif any(c.get("cvss", 0) >= 7.0 for c in cves):
            tech["cve_severity"] = "high"
        elif any(c.get("cvss", 0) >= 4.0 for c in cves):
            tech["cve_severity"] = "medium"
        elif cves:
            tech["cve_severity"] = "low"
    technologies.sort(key=lambda x: (-(x.get("cve_count") or 0), x["name"].lower()))
    return technologies, cve_source_default


async def detect_from_http(url: str) -> tuple[list[dict], str]:
    """Fingerprint via response headers + HTML/asset signals."""
    seen: set[str] = set()
    technologies: list[dict] = []

    try:
        with httpx.Client(timeout=18.0, follow_redirects=True, max_redirects=5) as client:
            resp = client.get(url, headers={"User-Agent": "AKILI-Fingerprint/1.0"})
            html = (resp.text or "")[:250000]
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        return [], "http-fingerprint"

    for raw_hdr, cat in EXTRA_HEADERS:
        val = headers.get(raw_hdr, "")
        if not val:
            continue
        if raw_hdr in ("server", "x-powered-by"):
            entry = _parse_banner(val, cat)
        elif raw_hdr == "x-generator":
            entry = _parse_banner(val, "Generator") or _tech_entry(val.split()[0], ["CMS"], None)
        else:
            ver = val.strip() if re.match(r"^[\d.]+$", val.strip()) else None
            entry = _tech_entry(cat, [cat], ver)
        if entry:
            _upsert_tech(technologies, seen, entry)

    gen = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
        html,
        re.I,
    ) or re.search(
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
        html,
        re.I,
    )
    if gen:
        g = gen.group(1).strip()
        parts = g.split()
        name = parts[0]
        ver = None
        for p in parts[1:]:
            if re.match(r"^[\d.]+$", p):
                ver = p
                break
        _upsert_tech(technologies, seen, _tech_entry(name, ["CMS"], ver, 90))

    for pattern, name, cats in HTML_HINTS:
        if re.search(pattern, html, re.I):
            _upsert_tech(technologies, seen, _tech_entry(name, cats))

    _scan_html_assets(html, technologies, seen)
    _scan_plugin_versions(html, technologies, seen)
    _scan_script_libraries(html, technologies, seen)

    if "kestrel" in {t["name"].lower() for t in technologies}:
        _upsert_tech(technologies, seen, _tech_entry("ASP.NET Core", ["Framework"], None, 85))

    technologies, cve_src = await _enrich_cves(technologies)
    return technologies, cve_src if cve_src != "none" else "http-fingerprint"


async def _detect_wappalyzer(url: str) -> list[dict]:
    webpage = WebPage.new_from_url(url, timeout=15)
    wappalyzer = Wappalyzer.latest()
    detected = wappalyzer.analyze_with_categories(webpage) or {}
    out = []
    for tech_name, tech_data in detected.items():
        if not isinstance(tech_data, dict):
            tech_data = {}
        version = tech_data.get("version")
        if version and not isinstance(version, str):
            version = str(version)
        cats = tech_data.get("categories") or {}
        out.append({
            "name": tech_name,
            "categories": list(cats.values()) if isinstance(cats, dict) else list(cats),
            "version": version,
            "confidence": tech_data.get("confidence", 100),
            "cves": [],
            "cve_count": 0,
            "cve_severity": "none",
            "cve_source": "none",
        })
    return out


async def detect_technologies(url: str) -> tuple[list[dict], str]:
    import asyncio

    technologies, cve_source_default = await detect_from_http(url)

    if WAPPALYZER_AVAILABLE:
        try:
            extra = await asyncio.wait_for(_detect_wappalyzer(url), timeout=25.0)
            if extra:
                _merge_wappalyzer(technologies, extra)
                technologies, enriched_source = await _enrich_cves(technologies)
                if enriched_source != "none":
                    cve_source_default = enriched_source
                return technologies, "wappalyzer+http"
        except Exception:
            pass

    return technologies, cve_source_default


async def detect_technology_changes(domain: str, current_techs: list) -> list[dict]:
    from database import get_last_tech_snapshot

    previous = get_last_tech_snapshot(domain)
    if not previous:
        return []

    changes = []
    prev_map = {t["name"]: t for t in previous}
    curr_map = {t["name"]: t for t in current_techs}

    for name, tech in curr_map.items():
        if name not in prev_map:
            changes.append({
                "type": "new_technology",
                "technology": name,
                "message": f"{name} detected — was not present last scan",
                "severity": "info",
            })
        elif tech.get("version") != prev_map[name].get("version"):
            old_v = prev_map[name].get("version")
            new_v = tech.get("version")
            old_cve_count = len(prev_map[name].get("cves", []))
            new_cve_count = len(tech.get("cves", []))
            changes.append({
                "type": "version_change",
                "technology": name,
                "old_version": old_v,
                "new_version": new_v,
                "old_cve_count": old_cve_count,
                "new_cve_count": new_cve_count,
                "message": f"{name} updated from {old_v or '?'} to {new_v or '?'}. CVEs: {old_cve_count} → {new_cve_count}",
                "severity": "high" if new_cve_count > old_cve_count else "info",
            })

    for name in prev_map:
        if name not in curr_map:
            changes.append({
                "type": "removed_technology",
                "technology": name,
                "message": f"{name} no longer detected",
                "severity": "info",
            })

    return changes


def run(url: str, context: dict) -> dict:
    domain = _extract_domain(url)
    findings = []

    try:
        technologies, cve_source = run_async(detect_technologies(url), timeout=60)
    except Exception as e:
        return {
            "tool": "fingerprint",
            "severity": "INFO",
            "title": "Technology fingerprint",
            "detail": str(e)[:100],
            "summary": "Technology detection failed",
            "raw": {"technologies": [], "error": str(e), "detection_method": "error"},
            "findings": [],
        }

    tech_changes = []
    try:
        tech_changes = run_async(detect_technology_changes(domain, technologies), timeout=15)
    except Exception:
        pass

    for tech in technologies:
        if tech.get("cve_severity") in ("critical", "high"):
            findings.append({
                "severity": tech["cve_severity"].upper(),
                "name": f"CVEs in {tech['name']} {tech.get('version') or ''}".strip(),
                "explanation": f"{tech['cve_count']} known CVE(s) from {tech.get('cve_source', 'public databases')}.",
                "recommendation": "Patch or upgrade this component.",
            })

    context["tech_stack"] = technologies
    context["tech_changes"] = tech_changes
    context["domain"] = domain

    from database import save_tech_snapshot

    save_tech_snapshot(
        snapshot_id=str(uuid.uuid4()),
        domain=domain,
        scan_id=context.get("scan_id", ""),
        technologies=technologies,
    )

    with_ver = sum(1 for t in technologies if t.get("version"))
    method = "wappalyzer+http" if "wappalyzer" in (cve_source or "") else (
        "wappalyzer" if WAPPALYZER_AVAILABLE and len(technologies) > 3 else "http-fingerprint"
    )

    return {
        "tool": "fingerprint",
        "severity": "HIGH" if any(t.get("cve_severity") == "critical" for t in technologies) else "INFO",
        "title": "Technology fingerprint + CVE",
        "detail": f"{len(technologies)} technologies ({with_ver} with versions)",
        "summary": (
            f"Detected {len(technologies)} technologies ({with_ver} versioned)"
            if technologies
            else "No technologies detected — site may block scanners"
        ),
        "raw": {
            "technologies": technologies,
            "tech_stack": technologies,
            "tech_changes": tech_changes,
            "cve_data_source": cve_source,
            "detection_method": method,
            "total_cves": sum(t.get("cve_count", 0) for t in technologies),
            "versioned_count": with_ver,
        },
        "findings": findings,
    }
