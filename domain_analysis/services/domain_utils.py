import os
import tempfile
import tldextract
import ipaddress
from typing import Optional

# Pre-initialize extractor with a proper cache directory
# (cache_dir=True creates a literal "True" folder — this is a known tldextract bug)
_TLDEXTRACT_CACHE = os.path.join(tempfile.gettempdir(), '.safeclick_tldextract_cache')
extractor = tldextract.TLDExtract(cache_dir=_TLDEXTRACT_CACHE)

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


def extract_canonical_labels(url_or_host: str) -> dict:
    """
    Extracts canonical domain labels, decoded IDNA tokens, and domain parts.
    Single source of truth for domain parsing across all engines.
    """
    if not url_or_host:
        return {
            "fqdn": "",
            "registrable_domain": "",
            "subdomain": "",
            "main_part": "",
            "tokens": set(),
            "labels": []
        }

    raw = url_or_host.strip().lower()
    # Remove scheme if present
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    # Remove path, query, fragment
    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    # Remove port if present
    if ":" in raw and not raw.startswith("["):  # not IPv6 literal
        raw = raw.split(":", 1)[0]
    raw = raw.rstrip(".")

    # Decode IDNA / Punycode if any label starts with xn--
    try:
        import idna
        decoded_labels = []
        for part in raw.split("."):
            if part.startswith("xn--"):
                try:
                    decoded_labels.append(idna.decode(part).lower())
                except Exception:
                    decoded_labels.append(part)
            else:
                decoded_labels.append(part)
        raw = ".".join(decoded_labels)
    except Exception:
        pass

    info = extract_domain_info(raw)
    registrable = (info.get("registrable_domain") or raw).lower()
    subdomain = (info.get("subdomain") or "").lower()
    domain_name = (info.get("domain") or "").lower()
    fqdn = (info.get("fqdn") or raw).lower()

    # Extract all discrete tokens split by common delimiters ('-', '_', '.')
    import re
    tokens = set()
    for part in (subdomain, domain_name):
        if part:
            sub_tokens = [t for t in re.split(r'[-_.]+', part) if t]
            tokens.update(sub_tokens)

    labels = [l for l in raw.split(".") if l]

    return {
        "fqdn": fqdn,
        "registrable_domain": registrable,
        "subdomain": subdomain,
        "main_part": domain_name,
        "tokens": tokens,
        "labels": labels
    }