import dns.resolver
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

def get_reliable_resolver():
    """Returns a DNS resolver with fixed nameservers and timeouts."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    resolver.timeout = 1.5
    resolver.lifetime = 1.5
    return resolver

def analyze_dns(domain: str) -> Dict[str, Any]:
    """
    Analyzes DNS records for suspicious configurations.
    """
    if not domain:
        return {"status": "error", "error": "No domain provided"}

    details = {
        "resolves": False,
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
            a_answers = resolver.resolve(domain, 'A')
            details["a_records"] = [str(rdata) for rdata in a_answers]
            details["resolves"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            details["errors"].append(f"A record error: {str(e)}")

        # MX Records
        try:
            mx_answers = resolver.resolve(domain, 'MX')
            details["mx_records"] = [str(rdata.exchange).rstrip('.') for rdata in mx_answers]
            details["has_mx"] = len(details["mx_records"]) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            details["errors"].append(f"MX record error: {str(e)}")

        # NS Records
        try:
            ns_answers = resolver.resolve(domain, 'NS')
            details["ns_records"] = [str(rdata.target).rstrip('.') for rdata in ns_answers]
            details["has_ns"] = len(details["ns_records"]) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            details["errors"].append(f"NS record error: {str(e)}")

        # Check for abnormal configurations
        # e.g., missing MX and NS records for a generic domain
        if details["resolves"] and not details["has_mx"] and not details["has_ns"]:
            details["abnormal_config"] = True

        return {
            "status": "ok",
            "details": details
        }

    except Exception as e:
        logger.debug(f"DNS analysis failed for {domain}: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "details": details
        }