import urllib.parse
import re
from typing import Dict, Any
from .domain_utils import extract_domain_info, is_ip_address

def analyze_url_structure(url: str) -> Dict[str, Any]:
    """
    Analyzes the structure of a URL for potential phishing indicators.
    """
    if not url:
        return {
            "status": "error",
            "error": "No URL provided",
            "details": {}
        }

    try:
        parsed = urllib.parse.urlparse(url)
        
        # Check for host/netloc
        host = parsed.netloc or parsed.hostname
        if not host:
            return {
                "status": "error",
                "error": "Malformed URL: missing host",
                "details": {}
            }

        # IP Address check
        is_ip = is_ip_address(host)
        
        # TLD/Domain extraction
        domain_info = extract_domain_info(url)
        
        # Subdomain counting
        subdomain = domain_info.get("subdomain", "")
        # Number of parts in subdomain: 'a.b.c' -> 3 parts
        subdomain_parts = subdomain.split(".") if subdomain else []
        subdomain_count = len(subdomain_parts)
        
        # Special character detection in path
        path = parsed.path
        # Detect %XX or @ or other suspicious chars
        has_encoded_chars = bool(re.search(r"%[0-9a-fA-F]{2}", path))
        
        # Decode URL to catch encoded evasions (like %40 for @)
        decoded_url = urllib.parse.unquote(url)
        has_at_symbol = "@" in decoded_url
        
        return {
            "status": "ok",
            "details": {
                "length": len(url),
                "is_ip": is_ip,
                "subdomain_count": subdomain_count,
                "subdomains": subdomain_parts,
                "domain": domain_info.get("domain"),
                "suffix": domain_info.get("suffix"),
                "has_encoded_chars": has_encoded_chars,
                "has_at_symbol": has_at_symbol,
            }
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "details": {}
        }