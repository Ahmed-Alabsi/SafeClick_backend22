"""
Threat Intelligence Engine (v5.1 — Anti-Evasion + Shared-Platform-Aware)
───────────────────────────────────────────────────────────────────────
Consolidates and matches against the structured master blacklist.
Implements intelligent 4-tier matching with shared-hosting awareness:

1. Exact URL match         (safest — works for ALL platforms)
2. Exact Host match        (safe  — catches specific subdomains)
3. Base Domain match       (SKIPPED for shared hosting platforms)
4. Domain Suffix match     (SKIPPED for shared hosting platforms)

v5.1: All URLs are canonicalized before storage AND matching
to prevent evasion via encoding, case, or trailing slashes.
"""

import logging
import threading
import csv
import time
from typing import Dict, Any, Optional
from pathlib import Path
from urllib.parse import urlparse, unquote, urlunparse

from .constants import SHARED_HOSTING_PROVIDERS

logger = logging.getLogger(__name__)

# Global memory cache
_THREAT_CACHE = {
    "urls": set(),
    "hosts": set(),
    "domains": set(),
    "domains_suffixes": set() 
}
_CACHE_LOCK = threading.Lock()
_LAST_FETCH = 0

# Paths for local data
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
MASTER_BLACKLIST_FILE = DATA_DIR / "master_blacklist.csv"


def _canonicalize_url(url: str) -> str:
    """
    Normalizes a URL for consistent matching.
    Prevents evasion via:
      - Percent-encoding:  evil.com/%6C%6F%67%69%6E → evil.com/login
      - Case differences:  evil.com/LOGIN → evil.com/login
      - Trailing slashes:  evil.com/login/ → evil.com/login
      - Missing scheme:    evil.com → http://evil.com
    """
    try:
        # Decode and lowercase everything for robust blacklist matching
        decoded = unquote(url).lower()
        parsed = urlparse(decoded if "://" in decoded else f"http://{decoded}")
        scheme = parsed.scheme or "http"
        netloc = parsed.netloc
        # Strip www.
        if netloc.startswith("www."):
            netloc = netloc[4:]
        # Normalize path: strip trailing slash, but keep root as "/"
        path = parsed.path.rstrip("/") or "/"
        # Reconstruct without fragment
        return urlunparse((scheme, netloc, path, "", parsed.query, ""))
    except Exception:
        return url.lower().rstrip("/")


def extract_full_host(url: str) -> Optional[str]:
    """Extracts the full hostname from a URL, stripping www. prefix."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.netloc.lower().split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return None


def extract_base_domain(url: str) -> Optional[str]:
    """
    PSL-aware domain extraction using tldextract.
    
    For normal domains:   google.com → google.com
    For shared platforms: my-cv.vercel.app → my-cv.vercel.app (NOT vercel.app)
    """
    try:
        from .domain_utils import extractor
        ext = extractor(url if "://" in url else f"http://{url}")
        if ext.registered_domain:
            return ext.registered_domain
        # Fallback: if tldextract returns only suffix (e.g., just "vercel.app")
        if ext.suffix:
            return ext.suffix
    except Exception:
        pass
    # Ultimate fallback: naive extraction
    host = extract_full_host(url)
    if not host:
        return None
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def extract_public_suffix(url: str) -> Optional[str]:
    """
    Returns the public suffix of a URL (e.g., 'vercel.app', 'com', 'co.uk').
    Used to detect shared hosting platforms via PSL.
    """
    try:
        from .domain_utils import extractor
        ext = extractor(url if "://" in url else f"http://{url}")
        return ext.suffix.lower() if ext.suffix else None
    except Exception:
        return None


def _is_shared_platform(url: str, domain: str) -> bool:
    """
    Determines if a URL is hosted on a shared/multi-tenant platform.
    Uses THREE layers for maximum reliability:
    
    Layer 1: Explicit domain match (instant — covers 'vercel.app' directly)
    Layer 2: Host suffix walk  (catches subdomains like 'my-cv.vercel.app')
    Layer 3: PSL suffix check  (dynamic fallback for new platforms)
    """
    # Layer 1: Direct match — domain IS the provider (e.g. domain='vercel.app')
    if domain in SHARED_HOSTING_PROVIDERS:
        return True
    
    # Layer 2: Walk up the hostname to find a provider suffix
    #   e.g. host='my-cv.vercel.app' → check 'vercel.app' → found!
    host = extract_full_host(url)
    if host:
        parts = host.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in SHARED_HOSTING_PROVIDERS:
                return True
    
    # Layer 3: PSL-based check (fallback for unlisted providers)
    suffix = extract_public_suffix(url)
    if suffix and suffix in SHARED_HOSTING_PROVIDERS:
        return True
    
    return False


def _load_master_blacklist():
    """
    Reads the consolidated master_blacklist.csv into the structured memory cache.
    
    CRITICAL FIX (v5.0): For shared hosting platforms (vercel.app, github.io, etc.),
    the base domain is NEVER added to cache["domains"] or cache["domains_suffixes"].
    Only the exact URL and exact host (subdomain) are stored.
    
    This prevents false positives where blocking 'amazon-clone.vercel.app'
    would incorrectly block ALL vercel.app sites.
    """
    cache = {
        "urls": set(),
        "hosts": set(),
        "domains": set(),
        "domains_suffixes": set()
    }
    
    if not MASTER_BLACKLIST_FILE.exists():
        logger.warning(f"Master blacklist not found at {MASTER_BLACKLIST_FILE}")
        return cache

    skipped_providers = 0

    try:
        # Use string path conversion for robust Windows handling
        target_path = str(MASTER_BLACKLIST_FILE.absolute())
        with open(target_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            # Schema: type,value,host,domain,source
            for row in reader:
                val = row.get("value")
                host = row.get("host")
                domain = row.get("domain")
                
                if not val: continue
                
                # 1. Exact URL storage (ALWAYS safe — most precise)
                #    Canonicalize for evasion-resistant matching
                cache["urls"].add(_canonicalize_url(val))
                
                # 2. Exact Host storage (ALWAYS safe — specific subdomain)
                if host:
                    cache["hosts"].add(host)
                    
                # 3. Base Domain storage — SKIP shared hosting platforms
                #    Blocking 'vercel.app' because 'amazon-clone.vercel.app' is
                #    phishing would be like banning an entire city because
                #    one resident committed a crime.
                if domain:
                    if domain in SHARED_HOSTING_PROVIDERS:
                        skipped_providers += 1
                    else:
                        cache["domains"].add(domain)
                        cache["domains_suffixes"].add(domain)
                    
        logger.info(
            f"Master Blacklist loaded: {len(cache['urls'])} URLs, "
            f"{len(cache['hosts'])} hosts, {len(cache['domains'])} domains "
            f"({skipped_providers} shared-platform entries excluded from domain-level blocking)"
        )
    except Exception as e:
        logger.error(f"Failed to load master blacklist: {e}")
    
    return cache


def refresh_threat_feeds():
    """Reloads the master blacklist from disk."""
    global _THREAT_CACHE, _LAST_FETCH
    with _CACHE_LOCK:
        now_ts = time.time()
        if now_ts - _LAST_FETCH < 1800 and any(_THREAT_CACHE.values()):
            return

        new_cache = _load_master_blacklist()
        _THREAT_CACHE = new_cache
        # T6 FIX: Only mark fetch time if we actually loaded data.
        # Previously, an empty/failed load set _LAST_FETCH, blocking retries for 30min.
        if any(new_cache.values()):
            _LAST_FETCH = now_ts
        else:
            logger.warning("[ThreatIntel] Blacklist loaded empty — will retry on next call.")


def get_threat_cache() -> Dict[str, set]:
    """Thread-safe access to the threat cache."""
    if not any(_THREAT_CACHE.values()):
        refresh_threat_feeds()
    return _THREAT_CACHE


def check_threat_intel(url: str) -> Dict[str, Any]:
    """
    Performs multi-level threat intelligence matching.
    
    Matching strategy:
        - Exact URL:  Always checked (precise, zero false positives)
        - Exact Host: Always checked (subdomain-level, safe for shared platforms)
        - Base Domain: ONLY for dedicated domains (NOT shared hosting)
        - Suffix:      ONLY for dedicated domains (NOT shared hosting)
    
    This prevents false positives on shared platforms (Vercel, GitHub Pages, etc.)
    while maintaining full detection for dedicated malicious domains.
    """
    if not url:
        return {"status": "error", "error": "No URL provided", "details": {"blacklisted": False}}

    try:
        host = extract_full_host(url)
        domain = extract_base_domain(url)
        
        if not host:
            raise ValueError("Invalid URL format")

        cache = get_threat_cache()
        
        # Determine if this URL is on a shared hosting platform
        is_shared = _is_shared_platform(url, domain)
        
        match_type = None
        evidence = None
        
        # Canonicalize the input URL for consistent matching
        canonical_url = _canonicalize_url(url)
        
        # ── Tier 1: Exact URL Match (ALWAYS — safest for ALL platforms) ──
        if canonical_url in cache["urls"]:
            match_type = "exact_url"
            evidence = f"Exact URL match in threat feed: {url}"
            
        # ── Tier 2: Exact Host Match (ALWAYS — safe subdomain-level check) ──
        elif host in cache["hosts"]:
            match_type = "host"
            evidence = f"Malicious Subdomain/Host blocked: {host}"
            
        # ── Tier 3: Base Domain Match (ONLY for dedicated domains) ──
        # SKIP for shared platforms: vercel.app, github.io, etc.
        elif not is_shared and domain in cache["domains"]:
            match_type = "domain"
            evidence = f"Domain '{domain}' is blacklisted"
            
        else:
            # ── Tier 4: Suffix Match (ONLY for dedicated domains) ──
            # SKIP for shared platforms to prevent cascading false positives
            if not is_shared:
                parts = host.split(".")
                for i in range(1, len(parts)):
                    parent = ".".join(parts[i:])
                    if parent in cache["domains_suffixes"]:
                        match_type = "subdomain"
                        evidence = f"Subdomain of blacklisted domain: {parent}"
                        break

        return {
            "status": "ok",
            "details": {
                "blacklisted": match_type is not None,
                "match_type": match_type,
                "evidence": evidence,
                "source": "Consolidated Master Blacklist",
                "is_shared_platform": is_shared,
                "cache_size": len(cache["urls"]) + len(cache["domains"])
            }
        }

    except Exception as e:
        logger.error(f"Threat Intel check error: {type(e).__name__}")
        return {
            "status": "error",
            "error": "Threat intelligence check failed",
            "details": {"blacklisted": False, "source": "Cache"}
        }

# For backward compatibility with older calls
check_openphish = check_threat_intel
