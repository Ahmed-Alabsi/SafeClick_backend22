"""
Threat Intelligence Engine
──────────────────────────
Fetches and caches phishing domain feeds from OpenPhish and PhishTank.
Provides O(1) in-memory blacklist lookups.

Uses a requests.Session for HTTP connection reuse (connection pooling),
avoiding TCP handshake overhead on repeated fetches.
"""

import requests
import logging
import threading
import csv
import time
from typing import Dict, Any
from .domain_utils import extract_domain

logger = logging.getLogger(__name__)

# Primary feed URLs
OPENPHISH_COMMUNITY_FEED = "https://openphish.com/feed.txt"
PHISHTANK_FEED = "http://data.phishtank.com/data/online-valid.csv"

# Global memory cache
_THREAT_CACHE = set()
_CACHE_LOCK = threading.Lock()
_LAST_FETCH = 0

# Reusable session for connection pooling
_session = None


def _get_session() -> requests.Session:
    """Returns a reusable requests.Session with pooling."""
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/120.0.0.0 Safari/537.36'
        })
        # Configure connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=2,
            pool_maxsize=5,
            max_retries=requests.adapters.Retry(total=2, backoff_factor=0.5)
        )
        _session.mount("http://", adapter)
        _session.mount("https://", adapter)
    return _session


def refresh_threat_feeds():
    """
    Fetches Threat Intelligence feeds and stores them in memory.
    Refreshes every 30 minutes to prevent IP banning during bulk tests.
    """
    global _THREAT_CACHE, _LAST_FETCH
    with _CACHE_LOCK:
        # Refresh every 30 minutes
        if time.time() - _LAST_FETCH < 1800 and len(_THREAT_CACHE) > 0:
            return

        new_cache = set()
        session = _get_session()

        # Fetch OpenPhish
        try:
            response = session.get(OPENPHISH_COMMUNITY_FEED, timeout=10, allow_redirects=True)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    domain = extract_domain(line.strip())
                    if domain:
                        new_cache.add(domain)
                logger.info(f"OpenPhish: loaded {len(new_cache)} domains")
        except requests.exceptions.Timeout:
            logger.warning("OpenPhish feed timed out")
        except requests.exceptions.ConnectionError:
            logger.warning("OpenPhish feed connection failed")
        except Exception as e:
            logger.warning(f"Failed to fetch OpenPhish feed: {type(e).__name__}")

        # Fetch PhishTank (with timeout safeguard)
        phishtank_count = 0
        try:
            response = session.get(PHISHTANK_FEED, timeout=15)
            if response.status_code == 200:
                reader = csv.reader(response.text.splitlines())
                next(reader, None)  # skip header
                for row in reader:
                    if len(row) > 1:
                        domain = extract_domain(row[1])
                        if domain:
                            new_cache.add(domain)
                            phishtank_count += 1
                logger.info(f"PhishTank: loaded {phishtank_count} additional domains")
        except requests.exceptions.Timeout:
            logger.warning("PhishTank feed timed out (15s)")
        except requests.exceptions.ConnectionError:
            logger.warning("PhishTank feed connection failed")
        except Exception as e:
            logger.warning(f"Failed to fetch PhishTank feed: {type(e).__name__}")

        if new_cache:
            _THREAT_CACHE = new_cache
            _LAST_FETCH = time.time()
            logger.info(f"Threat Intelligence Cache refreshed: {len(_THREAT_CACHE)} total malicious domains")


def get_threat_cache() -> set:
    """Thread-safe access to the threat cache, triggering a refresh if empty."""
    if not _THREAT_CACHE:
        refresh_threat_feeds()
    return _THREAT_CACHE


def check_openphish(url: str) -> Dict[str, Any]:
    """
    Checks if the URL/Domain appears in the locally cached threat intelligence feeds.
    Returns status 'ok' instantly (O(1)).
    """
    if not url:
        return {
            "status": "error",
            "error": "No URL provided",
            "details": {"blacklisted": False}
        }

    try:
        domain = extract_domain(url)
        if not domain:
            raise ValueError("Invalid URL format")

        threat_cache = get_threat_cache()
        is_blacklisted = domain in threat_cache

        return {
            "status": "ok",
            "details": {
                "blacklisted": is_blacklisted,
                "source": "OpenPhish/PhishTank",
                "cache_size": len(threat_cache)
            }
        }

    except Exception as e:
        logger.error(f"Threat Intel check error: {type(e).__name__}")
        return {
            "status": "error",
            "error": "Threat intelligence check failed",
            "details": {"blacklisted": False, "source": "Cache"}
        }
