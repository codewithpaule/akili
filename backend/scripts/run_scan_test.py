import requests, json, sys

BASE = "http://localhost:8001"
creds = {"email": "pauleruvwu@gmail.com", "password": "Paul123", "admin_pin": "1234"}

try:
    login = requests.post(f"{BASE}/api/v1/admin/login", json=creds, timeout=10)
except Exception as e:
    print("LOGIN ERROR:", str(e))
    sys.exit(1)

print("LOGIN STATUS:", login.status_code)
try:
    lj = login.json()
except Exception:
    print("LOGIN BODY:", login.text)
    sys.exit(1)

token = lj.get("token")
print("TOKEN:", bool(token))
if not token:
    print(json.dumps(lj, indent=2))
    sys.exit(1)

headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
scan_body = {
    "url": "https://example.com",
    "methods": ["GET", "POST"],
    "form_payload": {"q": "akili_test"},
    "diff": True,
}

try:
    r = requests.post(f"{BASE}/api/v1/scan/api", json=scan_body, headers=headers, timeout=30)
except Exception as e:
    print("SCAN ERROR:", str(e))
    sys.exit(1)

print("SCAN STATUS:", r.status_code)
try:
    print(json.dumps(r.json(), indent=2))
except Exception:
    print(r.text)
