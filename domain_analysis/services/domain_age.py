from datetime import datetime, timezone
from typing import Dict, Any
import logging
import whois
from .rdap_client import get_rdap_data

logger = logging.getLogger(__name__)

def get_domain_age(domain: str) -> Dict[str, Any]:
    """
    Calculates the domain age in days based on RDAP data, with WHOIS fallback.
    """
    if not domain:
        return {
            "status": "error",
            "error": "No domain provided",
            "details": {"age_days": 0}
        }

    # Try RDAP first (it's structured and faster usually)
    rdap_result = get_rdap_data(domain)
    creation_date = None

    if rdap_result and rdap_result.get("status") == "ok":
        creation_date_str = rdap_result.get("creation_date")
        if creation_date_str:
            try:
                dt_str = creation_date_str.replace("Z", "+00:00")
                creation_date = datetime.fromisoformat(dt_str)
            except Exception:
                pass

    # Fallback to WHOIS if RDAP failed or didn't provide a date
    if not creation_date:
        try:
            w = whois.whois(domain)
            if w and w.creation_date:
                # creation_date can be a list or a single datetime
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                # Ensure it has timezone info or is treated as UTC
                if creation_date and hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {str(e)}")
            creation_date = None

    if not creation_date:
        return {
            "status": "unknown",
            "details": {
                "age_days": 0,
                "error": "Could not retrieve registration date from RDAP or WHOIS"
            }
        }

    try:
        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days
        
        return {
            "status": "ok",
            "details": {
                "age_days": max(0, age_days),
                "creation_date": creation_date.isoformat(),
                "is_new": age_days < 30
            }
        }
    except Exception as e:
        return {
            "status": "unknown",
            "details": {
                "age_days": 0,
                "error": f"Age calculation error: {str(e)}"
            }
        }
