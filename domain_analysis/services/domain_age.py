from datetime import datetime, timezone
from typing import Dict, Any
import logging
import asyncio
import whois
from dateutil import parser as date_parser
from .rdap_client import get_rdap_data
from .async_utils import run_cpu_bound

try:
    from django.core.cache import cache
except Exception:
    cache = None

logger = logging.getLogger(__name__)

# Lazy loaded semaphore to control WHOIS and RDAP concurrency
_domain_age_sem = None

async def get_domain_age(domain: str) -> Dict[str, Any]:
    """
    Calculates the domain age in days based on RDAP data, with WHOIS fallback asynchronously.
    Includes an intrinsic Semaphore (concurrency limit) to avoid provider blocking (Rate Limit Isolation),
    and caches valid age data for 7 days in Redis.
    """
    if not domain:
        return {
            "status": "error",
            "error": "No domain provided",
            "details": {"age_days": 0}
        }

    domain_clean = domain.lower().strip()
    cache_key = f"domain_age:{domain_clean}"

    if cache:
        try:
            cached_res = cache.get(cache_key)
            if cached_res:
                logger.debug("Returning cached domain age for %s", domain_clean)
                return cached_res
        except Exception:
            pass

    # BUG #5 FIX: Always initialize last_error before any try/except block.
    # Previously, if RDAP returned None without raising an exception,
    # last_error was never set, making the 'last_error in locals()' check unreliable.
    last_error: str = ""

    global _domain_age_sem
    if _domain_age_sem is None:
        _domain_age_sem = asyncio.Semaphore(3)  # Max 3 concurrent WHOIS/RDAP lookups to avoid 429 Too Many Requests

    async with _domain_age_sem:
        # Try RDAP first (it's structured and faster usually)
        rdap_result = await get_rdap_data(domain)
        creation_date = None

        if rdap_result and rdap_result.get("status") == "ok":
            creation_date_str = rdap_result.get("creation_date")
            if creation_date_str:
                try:
                    # Use date_parser for superior ISO and non-ISO handling
                    creation_date = date_parser.parse(creation_date_str)
                    if creation_date.tzinfo is None:
                        creation_date = creation_date.replace(tzinfo=timezone.utc)
                except Exception:
                    pass

        # Fallback to WHOIS if RDAP failed or didn't provide a date
        if not creation_date:
            try:
                # whois module is blocking, so run it in a thread wrapper
                w = await run_cpu_bound(whois.whois, domain)
                if w and w.creation_date:
                    # creation_date can be a list or a single datetime
                    raw_date = w.creation_date
                    if isinstance(raw_date, list):
                        raw_date = raw_date[0]
                    
                    if isinstance(raw_date, datetime):
                        creation_date = raw_date
                    elif isinstance(raw_date, str):
                        creation_date = date_parser.parse(raw_date)
                    
                    # Ensure it has timezone info or is treated as UTC
                    if creation_date and hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is None:
                        creation_date = creation_date.replace(tzinfo=timezone.utc)
            except Exception as e:
                last_error = str(e)
                logger.debug(f"WHOIS lookup failed for {domain}: {last_error}")
                creation_date = None

        if not creation_date:
            # Differentiate network failures from hidden domains.
            # last_error is always initialized at function start (BUG #5 FIX).
            error_str = last_error.lower()
            is_network_error = any(k in error_str for k in ['timeout', 'getaddrinfo', 'connection', 'reset'])

            if is_network_error:
                return {
                    "status": "ok",
                    "details": {
                        "age_days": 0,
                        "is_new": False,  # Don't assume new on network error
                        "age_hidden": False,
                        "network_error": True,
                        "error": "Network timeout or DNS failure during WHOIS"
                    }
                }
            
            # IMPORTANT: Many ccTLDs and malicious domains hide their creation date or lack RDAP servers.
            # In an Enterprise risk engine, a hidden age is a signal, NOT an engine failure.
            # We return status: "ok" so the engine isn't marked as "DEGRADED".
            return {
                "status": "ok",
                "details": {
                    "age_days": 0,
                    "is_new": False, # Do not assume 0-day; let RiskScorer handle missing age
                    "age_hidden": True,
                    "network_error": False,
                    "error": "Could not retrieve registration date (Privacy Protected or No WHOIS)"
                }
            }

        try:
            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days
            
            res = {
                "status": "ok",
                "details": {
                    "age_days": max(0, age_days),
                    "creation_date": creation_date.isoformat(),
                    "is_new": age_days < 30,
                    "age_hidden": False
                }
            }
            if cache:
                try:
                    cache.set(cache_key, res, timeout=60 * 60 * 24 * 7)
                except Exception:
                    pass
            return res
        except Exception as e:
            return {
                "status": "error",
                "error": f"Age calculation error: {str(e)}",
                "details": {
                    "age_days": 0
                }
            }
