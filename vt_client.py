import os
import asyncio
import aiohttp
import base64
from urllib.parse import urlparse
from typing import Dict, Any, List

class VTClient:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.headers = {"x-apikey": self.api_key}
        self.base_url = "https://www.virustotal.com/api/v3"
        
        # Load whitelist to conserve API quota
        whitelist_env = os.getenv("WHITELIST_DOMAINS", "")
        self.whitelist = [d.strip().lower() for d in whitelist_env.split(",") if d.strip()]
        
        # Track last request time to enforce 15s throttle (Free tier: 4 req/min)
        self.last_request_time = 0.0

    async def _throttle(self):
        """Ensures we don't hit the 429 Too Many Requests limit."""
        now = asyncio.get_event_loop().time()
        elapsed = now - self.last_request_time
        if elapsed < 15.0:
            await asyncio.sleep(15.0 - elapsed)
        self.last_request_time = asyncio.get_event_loop().time()

    def _is_whitelisted(self, url: str) -> bool:
        """Checks if the domain is in our trusted allowlist."""
        try:
            domain = urlparse(url).netloc.lower()
            # Handle subdomains (e.g., mail.google.com -> google.com)
            return any(domain == w or domain.endswith(f".{w}") for w in self.whitelist)
        except Exception:
            return False

    async def check_url(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        if self._is_whitelisted(url):
            return {"positives": 0, "total": 0, "summary": "Whitelisted domain"}

        await self._throttle()
        
        # VT v3 requires base64 URL-safe encoding WITHOUT padding '='
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"{self.base_url}/urls/{url_id}"
        
        try:
            async with session.get(endpoint, headers=self.headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values())
                    return {
                        "positives": malicious + suspicious,
                        "total": total,
                        "summary": f"{malicious + suspicious}/{total} vendors flagged as malicious/suspicious"
                    }
                elif response.status == 404:
                    return {"positives": 0, "total": 0, "summary": "URL not found in VT"}
                else:
                    return {"error": f"HTTP {response.status}"}
        except Exception as e:
            return {"error": str(e)}

    async def check_hash(self, session: aiohttp.ClientSession, file_hash: str) -> Dict[str, Any]:
        await self._throttle()
        endpoint = f"{self.base_url}/files/{file_hash}"
        
        try:
            async with session.get(endpoint, headers=self.headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    return {
                        "positives": malicious,
                        "total": total,
                        "summary": f"{malicious}/{total} vendors flagged as malicious"
                    }
                elif response.status == 404:
                    return {"positives": 0, "total": 0, "summary": "Hash not found in VT"}
                else:
                    return {"error": f"HTTP {response.status}"}
        except Exception as e:
            return {"error": str(e)}
