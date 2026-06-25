import pytest
import httpx
from httpx import AsyncClient
import sys
import os

# Add parent directory to path to import main
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app

BASE = "http://testserver"


class TestPublicEndpoints:
    
    @pytest.mark.asyncio
    async def test_health(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.get("/api/v1/health")
            assert r.status_code == 200
            assert r.json()["status"] == "ok"
    
    @pytest.mark.asyncio
    async def test_public_email_scan_valid(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.post(
                "/api/v1/public/scan/email",
                json={"email": "test@gmail.com"}
            )
            assert r.status_code == 200
            data = r.json()
            assert "breach_found" in data
            assert "breach_count" in data
    
    @pytest.mark.asyncio
    async def test_public_email_invalid(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.post(
                "/api/v1/public/scan/email",
                json={"email": "notanemail"}
            )
            assert r.status_code == 400
    
    @pytest.mark.asyncio
    async def test_public_website_scan(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.post(
                "/api/v1/public/scan/website",
                json={"url": "https://example.com"}
            )
            assert r.status_code == 200
            data = r.json()
            assert "grade" in data
            assert "ssl_valid" in data
    
    @pytest.mark.asyncio
    async def test_public_private_ip_blocked(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.post(
                "/api/v1/public/scan/website",
                json={"url": "http://192.168.1.1"}
            )
            assert r.status_code == 400


class TestAPIKeyValidation:
    
    @pytest.mark.asyncio
    async def test_no_key_returns_401(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.post(
                "/api/v1/scan/website",
                json={"url": "https://example.com"}
            )
            # Should return 401 or 403 due to middleware
            assert r.status_code in [401, 403]
    
    @pytest.mark.asyncio
    async def test_wrong_key_returns_401(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.post(
                "/api/v1/scan/website",
                headers={"X-API-Key": "wrong_key"},
                json={"url": "https://example.com"}
            )
            assert r.status_code in [401, 403]
    
    @pytest.mark.asyncio
    async def test_docs_public(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.get("/docs")
            assert r.status_code == 200


class TestBreaches:
    
    @pytest.mark.asyncio
    async def test_nigeria_breaches_endpoint(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.get("/api/v1/breaches/nigeria")
            assert r.status_code == 200
            assert isinstance(r.json(), list)
    
    @pytest.mark.asyncio
    async def test_breach_has_required_fields(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.get("/api/v1/breaches/nigeria")
            if r.json():
                breach = r.json()[0]
                assert "breach" in breach or "name" in breach


class TestSSRFProtection:
    
    @pytest.mark.asyncio
    async def test_private_ip_blocked(self):
        private_urls = [
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://127.0.0.1",
            "http://172.16.0.1",
            "http://localhost"
        ]
        async with AsyncClient(app=app, base_url=BASE) as client:
            for url in private_urls:
                r = await client.post(
                    "/api/v1/public/scan/website",
                    json={"url": url}
                )
                assert r.status_code == 400, f"Should block {url}"


class TestScanLimits:
    
    @pytest.mark.asyncio
    async def test_scan_limit_functions(self):
        from database import check_and_increment_scan_limit, get_daily_scan_count, ScanUsage
        from database import get_db
        import secrets
        
        # Create a test user ID
        test_user_id = secrets.token_urlsafe(16)
        
        # Test initial count
        count = get_daily_scan_count(test_user_id)
        assert count == 0
        
        # Test increment
        new_count = check_and_increment_scan_limit(test_user_id)
        assert new_count == 1
        
        # Test second increment
        new_count = check_and_increment_scan_limit(test_user_id)
        assert new_count == 2
        
        # Test getting count
        count = get_daily_scan_count(test_user_id)
        assert count == 2
        
        # Clean up
        with get_db() as db:
            db.query(ScanUsage).filter(ScanUsage.user_id == test_user_id).delete()
            db.commit()


class TestPersonSearch:
    
    @pytest.mark.asyncio
    async def test_person_empty_name_blocked(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.post(
                "/api/v1/scan/person",
                json={"name": "", "keywords": ""}
            )
            assert r.status_code == 400


class TestPublicConfig:
    
    @pytest.mark.asyncio
    async def test_public_config_endpoint(self):
        async with AsyncClient(app=app, base_url=BASE) as client:
            r = await client.get("/api/v1/public-config")
            assert r.status_code == 200
            data = r.json()
            assert "GOOGLE_CLIENT_ID" in data


class TestRateLimiting:
    
    @pytest.mark.asyncio
    async def test_ip_rate_limiting(self):
        from public_scans import check_ip_rate_limit
        
        # Test first request
        result = check_ip_rate_limit("127.0.0.1", limit=30)
        assert result == True
        
        # Test multiple requests up to limit
        for i in range(29):
            result = check_ip_rate_limit("127.0.0.1", limit=30)
            assert result == True
        
        # Test exceeding limit
        result = check_ip_rate_limit("127.0.0.1", limit=30)
        assert result == False


class TestDatabaseSchema:
    
    @pytest.mark.asyncio
    async def test_scan_usage_table_exists(self):
        from database import get_db, ScanUsage
        from sqlalchemy import inspect
        
        with get_db() as db:
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            assert "scan_usage" in tables
            
            # Check columns
            columns = [col['name'] for col in inspector.get_columns('scan_usage')]
            assert "user_id" in columns
            assert "date" in columns
            assert "scan_count" in columns


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
