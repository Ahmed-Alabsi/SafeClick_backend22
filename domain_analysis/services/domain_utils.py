import tldextract
import ipaddress
from typing import Optional

# Pre-initialize extractor for performance
extractor = tldextract.TLDExtract(cache_dir=True)

def extract_domain_info(url: str) -> dict:
    """
    Extracts structured domain information using tldextract.
    """
    ext = extractor(url)
    
    # registrable_domain is the domain + suffix (e.g., google.com)
    # fqdn is the full thing (e.g., sub.google.com or 192.168.1.1)
    
    return {
        "subdomain": ext.subdomain,
        "domain": ext.domain,
        "suffix": ext.suffix,
        "registrable_domain": ext.registered_domain if ext.registered_domain else ext.domain,
        "fqdn": ext.fqdn
    }

def is_ip_address(host: str) -> bool:
    """
    Checks if the given host is a valid IP address.
    """
    if not host: return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def extract_domain(url: str) -> Optional[str]:
    """
    Returns the most appropriate domain/host for analysis.
    Uses registered_domain for heuristics, but falls back to FQDN or IP.
    """
    info = extract_domain_info(url)
    if info["registrable_domain"]:
        return info["registrable_domain"]
    return info["fqdn"] if info["fqdn"] else None