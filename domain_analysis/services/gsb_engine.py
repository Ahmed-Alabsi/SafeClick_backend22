"""
Google Safe Browsing (GSB) Engine
───────────────────────────────
Standalone integration for GSB API v4.
Provides high-trust threat detection signals.
"""

import aiohttp
import logging
from django.conf import settings
from typing import Dict, Any
from apps.core.utils.monitoring import monitor_engine

logger = logging.getLogger(__name__)

# API Documentation: https://developers.google.com/safe-browsing/v4/lookup-api
GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

@monitor_engine("gsb_standalone")
async def check_gsb_threat(url: str) -> Dict[str, Any]:
    """
    Checks a URL against Google Safe Browsing API.
    Returns standard EngineResult dictionary.
    """
    api_key = getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', '')
    
    if not api_key:
        # Fallback to local heuristic / mock if no API key is provided
        return {
            "status": "unknown",
            "details": "GSB API Key missing. Skipping standalone check."
        }

    payload = {
        "client": {
            "clientId": "safeclick-backend",
            "clientVersion": "2.0.0"
        },
        "threatInfo": {
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}]
        }
    }

    try:
        # BUG #6 FIX: Use the shared session pool instead of creating a new
        # ClientSession per request (aiohttp anti-pattern — causes fd leaks).
        from .async_utils import get_async_session
        session = await get_async_session()
        async with session.post(
            f"{GSB_API_URL}?key={api_key}",
            json=payload,
            timeout=aiohttp.ClientTimeout(total=5)
        ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    matches = data.get('matches', [])
                    if matches:
                        match = matches[0]
                        threat_type = match.get('threatType', 'UNKNOWN')
                        return {
                            "status": "malicious",
                            "threat_type": threat_type,
                            "platform": match.get('platformType', 'ANY'),
                            "details": f"🚨 Google Safe Browsing: Flagged as {threat_type}"
                        }
                    
                    return {
                        "status": "safe",
                        "details": "Google Safe Browsing: No threats detected."
                    }
                else:
                    logger.warning(f"GSB API returned status {response.status}")
                    return {"status": "skipped", "error": f"GSB API Error {response.status}", "details": "Google Safe Browsing: Skipped due to API limits"}
                    
    except Exception as e:
        logger.error(f"GSB Engine failure: {e}")
        return {"status": "skipped", "error": str(e), "details": "Google Safe Browsing: Connection failed"}
