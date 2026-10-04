import dns.asyncresolver
import dns.resolver
import logging
from typing import Dict, Any

try:
    from django.core.cache import cache
except Exception:
    cache = None

logger = logging.getLogger(__name__)


# ── DNS Resolution Status (Granular Intelligence) ────────────────────────
# Instead of a binary resolves=True/False, we track the exact outcome
# so the risk scorer can make context-aware decisions.
class DNSStatus:
    RESOLVED = "resolved"         # A record found → domain is live
    NXDOMAIN = "nxdomain"         # Confirmed: domain does not exist
    TIMEOUT = "timeout"           # Network issue: we simply couldn't verify
    SERVFAIL = "servfail"         # DNS server error
    NO_ANSWER = "no_answer"       # Domain exists but no A record
    UNKNOWN = "unknown"           # Fallback


def get_reliable_resolver():
    """Returns an async DNS resolver with multiple reliable nameservers and optimized timeouts."""
    resolver = dns.asyncresolver.Resolver()
    # Use a diverse set of redundant, high-performance global DNS providers
    resolver.nameservers = [
        '8.8.8.8',   # Google
        '1.1.1.1',   # Cloudflare
        '9.9.9.9',   # Quad9
        '8.8.4.4',   # Google Secondary
        '1.0.0.1',   # Cloudflare Secondary
    ]
    # Increased timeouts to handle temporary network congestion/VPN overhead
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    return resolver

async def resolve_ip_custom(domain: str) -> str | None:
    """Quickly resolves a domain to its A record IP using our reliable custom DNS resolver."""
    resolver = get_reliable_resolver()
    try:
        answers = await resolver.resolve(domain, 'A')
        for rdata in answers:
            return rdata.to_text()
    except Exception as e:
        logger.debug(f"[DNS Override] Failed to resolve {domain}: {e}")
    return None

async def analyze_dns(domain: str) -> Dict[str, Any]:
    """
    Analyzes DNS records for suspicious configurations asynchronously.
    Uses granular resolution status for context-aware risk scoring.
    Caches resolved DNS records in Redis for 24 hours.
    """
    if not domain:
        return {"status": "error", "error": "No domain provided"}

    domain_clean = domain.lower().strip()
    cache_key = f"dns_intel:{domain_clean}"

    if cache:
        try:
            cached_res = cache.get(cache_key)
            if cached_res:
                logger.debug("Returning cached DNS intel for %s", domain_clean)
                return cached_res
        except Exception:
            pass

    details = {
        "resolves": False,
        "resolution_status": DNSStatus.UNKNOWN,
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "has_mx": False,
        "has_ns": False,
        "abnormal_config": False,
        "errors": []
    }

    resolver = get_reliable_resolver()

    try:
        # A Records
        try:
            a_answers = await resolver.resolve(domain, 'A')
            details["a_records"] = [str(rdata) for rdata in a_answers]
            details["resolves"] = True
            details["resolution_status"] = DNSStatus.RESOLVED
        except dns.resolver.NXDOMAIN:
            details["resolution_status"] = DNSStatus.NXDOMAIN
        except dns.resolver.NoAnswer:
            details["resolution_status"] = DNSStatus.NO_ANSWER
        except dns.resolver.LifetimeTimeout:
            details["resolution_status"] = DNSStatus.TIMEOUT
            details["errors"].append("A record error: DNS query timed out")
        except Exception as e:
            err_str = str(e).lower()
            if "timed out" in err_str or "lifetime expired" in err_str:
                details["resolution_status"] = DNSStatus.TIMEOUT
            else:
                details["resolution_status"] = DNSStatus.SERVFAIL
            details["errors"].append(f"A record error: {str(e)}")

        # MX Records
        try:
            mx_answers = await resolver.resolve(domain, 'MX')
            details["mx_records"] = [str(rdata.exchange).rstrip('.') for rdata in mx_answers]
            details["has_mx"] = len(details["mx_records"]) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            details["errors"].append(f"MX record error: {str(e)}")

        # NS Records
        try:
            ns_answers = await resolver.resolve(domain, 'NS')
            details["ns_records"] = [str(rdata.target).rstrip('.') for rdata in ns_answers]
            details["has_ns"] = len(details["ns_records"]) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            details["errors"].append(f"NS record error: {str(e)}")

        # Check for abnormal configurations
        if details["resolves"] and not details["has_mx"] and not details["has_ns"]:
            details["abnormal_config"] = True

        res = {
            "status": "ok",
            "details": details
        }
        if cache and details.get("resolution_status") not in (DNSStatus.TIMEOUT, DNSStatus.SERVFAIL):
            try:
                cache.set(cache_key, res, timeout=86400)
            except Exception:
                pass
        return res

    except Exception as e:
        logger.debug(f"DNS analysis failed for {domain}: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "details": details
        }