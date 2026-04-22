"""
RDAP Client
────────────
Fetches RDAP (Registration Data Access Protocol) data for domain age calculation.

Uses a shared aiohttp.ClientSession for HTTP connection pooling.
"""

import aiohttp
import asyncio
import logging
from typing import Optional, Dict
from builtins import Exception
from .async_utils import get_async_session

logger = logging.getLogger(__name__)

async def get_rdap_data(domain: str) -> Optional[Dict]:
    """
    Fetches RDAP data for a given domain using rdap.org redirector.
    Runs asynchronously.
    """
    if not domain:
        return None

    url = f"https://rdap.org/domain/{domain}"

    try:
        session = await get_async_session()
        
        async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=5.0)) as response:
            if response.status == 404:
                return {"status": "not_found"}

            if response.status != 200:
                return {"status": "error", "error": f"HTTP {response.status}"}

            data = await response.json()
            
            # Comprehensive event action search
            REGISTRATION_EVENTS = {"registration", "created", "registration date", "creation"}
            
            events = data.get("events", [])
            
            # Loop 1: High-confidence registration events
            for event in events:
                if event.get("eventAction", "").lower() in REGISTRATION_EVENTS:
                    date_str = event.get("eventDate")
                    if date_str:
                        return {
                            "status": "ok",
                            "creation_date": date_str,
                            "method": "rdap"
                        }
            
            # Loop 2: Fallback to earliest event
            if events:
                try:
                    from dateutil import parser as date_parser
                    valid_events = [e for e in events if e.get("eventDate")]
                    if valid_events:
                        def _parse_event_date(e):
                            try:
                                return date_parser.parse(e["eventDate"])
                            except Exception:
                                # T5 FIX: Fallback to string comparison if parsing fails
                                return e["eventDate"]
                        earliest = min(valid_events, key=_parse_event_date)
                        return {
                            "status": "ok",
                            "creation_date": earliest.get("eventDate"),
                            "method": "rdap_earliest"
                        }
                except Exception:
                    pass

            return {"status": "not_found", "message": "No creation date found in RDAP record"}

    except asyncio.TimeoutError:
        return {"status": "error", "error": "timeout"}
    except aiohttp.ClientError:
        return {"status": "error", "error": "connection_failed"}
    except Exception as e:
        logger.debug(f"RDAP lookup error for {domain}: {type(e).__name__}")
        return {"status": "error", "error": "lookup_failed"}