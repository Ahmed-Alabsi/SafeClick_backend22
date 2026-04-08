"""
RDAP Client
────────────
Fetches RDAP (Registration Data Access Protocol) data for domain age calculation.

Uses a requests.Session for HTTP connection pooling when making multiple
sequential lookups.
"""

import requests
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)

# Reusable session for connection pooling
_session = None


def _get_session() -> requests.Session:
    """Returns a reusable requests.Session."""
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update({
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "SafeClick-RDAP-Client/1.0"
        })
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=2,
            pool_maxsize=5,
            max_retries=requests.adapters.Retry(total=1, backoff_factor=0.3)
        )
        _session.mount("https://", adapter)
    return _session


def get_rdap_data(domain: str) -> Optional[Dict]:
    """
    Fetches RDAP data for a given domain using rdap.org redirector.
    """
    if not domain:
        return None

    url = f"https://rdap.org/domain/{domain}"

    try:
        session = _get_session()
        response = session.get(url, timeout=2.5, allow_redirects=True)

        if response.status_code == 404:
            return {"status": "not_found"}

        if response.status_code != 200:
            return {"status": "error", "error": f"HTTP {response.status_code}"}

        data = response.json()

        # Standard RDAP registration event check
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                return {
                    "status": "ok",
                    "creation_date": event.get("eventDate")
                }

        # Alternative event names
        for event in data.get("events", []):
            if event.get("eventAction") in ["created", "registration date"]:
                return {
                    "status": "ok",
                    "creation_date": event.get("eventDate")
                }

        return {"status": "not_found", "message": "No registration event found"}

    except requests.exceptions.Timeout:
        return {"status": "error", "error": "timeout"}
    except requests.exceptions.ConnectionError:
        return {"status": "error", "error": "connection_failed"}
    except Exception as e:
        logger.debug(f"RDAP lookup error for {domain}: {type(e).__name__}")
        return {"status": "error", "error": "lookup_failed"}