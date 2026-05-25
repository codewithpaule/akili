import requests

try:
    r = requests.get('http://localhost:8001/api/v1/health', timeout=5)
    print('STATUS', r.status_code)
    print(r.text)
except Exception as e:
    print('ERROR', e)
