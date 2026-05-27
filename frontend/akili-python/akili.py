"""AKILI Python SDK — minimal client."""

import requests


class Client:
    def __init__(self, api_key: str, sandbox: bool = False, base_url: str = None):
        self.api_key = api_key
        # Default to deployed Fly backend API
        self.base_url = base_url or ("https://akili.fly.dev/api/v1/sandbox" if sandbox else "https://api.akili.com.ng/api/v1")
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        }

    def scan_website(self, url: str) -> dict:
        response = requests.post(
            f"{self.base_url}/scan/website",
            headers=self.headers,
            json={"url": url},
            timeout=120,
        )
        response.raise_for_status()
        return response.json() if response.headers.get("content-type", "").startswith("application/json") else {"raw": response.text}

    def search_person(self, name: str, keywords: str = "") -> dict:
        response = requests.post(
            f"{self.base_url}/scan/person",
            headers=self.headers,
            json={"name": name, "keywords": keywords},
            timeout=120,
        )
        response.raise_for_status()
        return response.json() if "application/json" in response.headers.get("content-type", "") else {"raw": response.text}

    def get_report(self, scan_id: str) -> dict:
        response = requests.get(
            f"{self.base_url}/report/{scan_id}",
            headers=self.headers,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()
