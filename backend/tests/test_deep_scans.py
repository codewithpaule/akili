import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPortScanner:
    
    def test_port_scanner_import(self):
        """Test that port scanner module can be imported."""
        from tools.port_scanner import run_port_scan
        assert run_port_scan is not None
    
    def test_common_ports_defined(self):
        """Test that common ports are defined."""
        from tools.port_scanner import COMMON_PORTS
        assert len(COMMON_PORTS) > 0
        assert 80 in COMMON_PORTS
        assert 443 in COMMON_PORTS


class TestTechFingerprint:
    
    def test_tech_fingerprint_import(self):
        """Test that tech fingerprint module can be imported."""
        from tools.tech_fingerprint import run_tech_fingerprint
        assert run_tech_fingerprint is not None
    
    def test_tech_patterns_defined(self):
        """Test that technology patterns are defined."""
        from tools.tech_fingerprint import TECH_PATTERNS
        assert len(TECH_PATTERNS) > 0
        assert "WordPress" in TECH_PATTERNS
        assert "Nginx" in TECH_PATTERNS

    def test_tech_version_patterns_are_flexible(self):
        """Test version detection from headers and asset URLs."""
        from tools.tech_fingerprint import detect_version

        html = '<script src="/static/jquery.min.js?ver=3.7.1"></script>'
        headers = {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2.12"}
        assert detect_version("jQuery", html, {}) == "3.7.1"
        assert detect_version("Nginx", "", headers) == "1.24.0"
        assert detect_version("PHP", "", headers) == "8.2.12"


class TestCVELookup:
    
    def test_cve_lookup_import(self):
        """Test that CVE lookup module can be imported."""
        from tools.cve_lookup import run_cve_lookup
        assert run_cve_lookup is not None
    
    def test_known_vulnerabilities_defined(self):
        """Test that known vulnerabilities database is defined."""
        from tools.cve_lookup import KNOWN_VULNERABILITIES
        assert len(KNOWN_VULNERABILITIES) > 0
        assert "WordPress" in KNOWN_VULNERABILITIES


class TestLinkCrawler:
    
    def test_link_crawler_import(self):
        """Test that link crawler module can be imported."""
        from tools.link_crawler import run_link_crawler
        assert run_link_crawler is not None
    
    def test_common_hidden_paths_defined(self):
        """Test that common hidden paths are defined."""
        from tools.link_crawler import COMMON_HIDDEN_PATHS
        assert len(COMMON_HIDDEN_PATHS) > 0
        assert "/admin" in COMMON_HIDDEN_PATHS
        assert "/.env" in COMMON_HIDDEN_PATHS


class TestExposedFiles:

    def test_exposed_probe_catalog_is_deep(self):
        """Test that exposed-file checks include admin, secrets, backups, and infra paths."""
        from tools.exposed import PROBES

        paths = {path for path, _ in PROBES}
        assert len(PROBES) >= 150
        assert "/admin" in paths
        assert "/.env.production" in paths
        assert "/backup.zip" in paths
        assert "/phpmyadmin" in paths
        assert "/actuator/env" in paths

    def test_exposed_probe_rejects_custom_200_missing_page(self):
        """Test that custom 200 error pages are not treated as real files."""
        from tools.page_verify import looks_like_custom_miss, path_exists

        hit = {"status": 200, "location": "", "title": "not found", "hash": "abc", "content_length": 1024, "text": "404 not found"}
        miss = {"status": 200, "location": "", "title": "not found", "hash": "abc", "content_length": 1010, "text": "404 not found"}
        assert looks_like_custom_miss(hit, [miss])
        soft_env = {
            "status": 200,
            "final_url": "https://example.com/",
            "text": "<html><title>Page not found</title><body>Sorry</body></html>",
            "content_type": "text/html",
        }
        assert not path_exists("/.env", soft_env, [miss])


class TestSubdomains:
    
    def test_subdomains_import(self):
        """Test that subdomains module can be imported."""
        from tools.subdomains import run
        assert run is not None
    
    def test_common_subdomains_defined(self):
        """Test that common subdomains are defined."""
        from tools.subdomains import COMMON_SUBDOMAINS
        assert len(COMMON_SUBDOMAINS) > 0
        assert "www" in COMMON_SUBDOMAINS
        assert "admin" in COMMON_SUBDOMAINS


class TestAgentIntegration:
    
    def test_agent_includes_deep_scans(self):
        """Test that agent.py includes deep scan tools."""
        from agent import TOOL_MAP, TOOL_DEFINITIONS

        tool_names = {d["function"]["name"] for d in TOOL_DEFINITIONS}
        assert "port_scanner" in tool_names
        assert "tech_fingerprint" in tool_names
        assert "link_crawler" in tool_names
        assert "cve_lookup" in tool_names
        assert "web_search" in tool_names

        assert "port_scanner" in TOOL_MAP
        assert "tech_fingerprint" in TOOL_MAP
        assert "cve_lookup" in TOOL_MAP
        assert "link_crawler" in TOOL_MAP


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
