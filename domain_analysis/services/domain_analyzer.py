import logging
import json
import hashlib
import asyncio
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, unquote
import os
import datetime

# Safe Django import
django_available = False
try:
    import django
    from django.conf import settings
    if settings.configured:
        from django.utils import timezone
        django_available = True
except Exception:
    pass

try:
    from django.core.cache import cache
except ImportError:
    cache = None

from apps.core.utils.monitoring import monitor_engine
from .domain_utils import extract_domain, extract_domain_info
from .domain_age import get_domain_age
from .typosquatting_engine import detect_typosquatting
from .url_feature_engine import analyze_url_structure
from .phishing_pattern_engine import detect_phishing_patterns
from .homoglyph_engine import detect_homoglyph_attack
from .dns_intelligence_engine import analyze_dns
from .ssl_intelligence_engine import analyze_ssl
from .threat_intelligence import check_openphish
from .url_unshortener_engine import unshorten_url, is_shortened_url
from .risk_scoring import RiskScorer
from .bloom_filter import get_bloom
from .async_utils import (
    execute_with_retry_and_timeout,
    run_cpu_bound,
    DNS_CIRCUIT_BREAKER
)

logger = logging.getLogger(__name__)

def initialize_engines():
    """
    Explicitly warms up all heavy data artifacts (Bloom Filter, Trie, Threat Intelligence).
    Ensures that real-time analysis doesn't hit lazy-loading timeouts.
    """
    logger.info("Initializing Domain Analysis Engines (Warm-up)...")
    try:
        from .bloom_filter import get_bloom
        from .trie_index import get_trie
        from .threat_intelligence import refresh_threat_feeds
        
        # Trigger data loading
        get_bloom()
        get_trie()
        refresh_threat_feeds()
        logger.info("All engines stabilized and datasets loaded.")
    except Exception as e:
        logger.error(f"Engine initialization failed: {e}")


# ── Open Redirect Parameter Names ─────────────────────────────────────
_REDIRECT_PARAMS = frozenset([
    "url", "redirect", "redirect_uri", "redirect_url", "return", "returnto",
    "return_url", "returnurl", "next", "target", "dest", "destination",
    "rurl", "go", "continue", "forward", "out", "link", "goto",
    "callback", "ret", "service", "ref", "referer", "to", "redir",
])


def _extract_open_redirect_target(url: str) -> Optional[str]:
    """
    Detects Open Redirect wrappers and extracts the embedded destination URL.
    """
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=False)
        for param_name in _REDIRECT_PARAMS:
            values = params.get(param_name, [])
            for val in values:
                decoded = unquote(val)
                if decoded.startswith(("http://", "https://")):
                    return decoded
    except Exception:
        pass
    return None

async def _run_engine_safe(name: str, coro) -> tuple:
    """Wraps an awaitable engine to ensure isolated execution, standard schema, and latency tracking."""
    
    # We dynamically create a wrapper to use our central decorator
    @monitor_engine(name)
    async def _execute_coro():
        return await coro
        
    result = await _execute_coro()
    return name, result


async def analyze_domain(url: str, use_cache: bool = True, lite_mode: bool = False) -> Dict[str, Any]:
    """
    Orchestrates the domain analysis process with parallel Async IO engines,
    Circuit Breakers, Retries, and clean CPU vs I/O separation.
    """

    # Ensure scheme exists for proper URL parsing, default to http://
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    original_url = url
    unshortener_result = None
    open_redirect_result = None

    # ── PRE-PROCESSING: URL Unshortening ─────────────────────────────────
    try:
        was_shortener = is_shortened_url(url)
        unshortener_result = await unshorten_url(url)
        
        final_url = url
        if unshortener_result.get("status") == "ok":
            resolved = unshortener_result.get("details", {}).get("final_url")
            if resolved and resolved != url:
                final_url = resolved
        
        # Suspect unresolvable shortener links
        if was_shortener and is_shortened_url(final_url):
            error_msg = unshortener_result.get("error", "Unable to resolve short link destination (Network Error or Dead Link)")
            
            # Distinguish between our backend network failing vs a dead link
            is_net_err = any(k in error_msg.lower() for k in ['timeout', 'getaddrinfo', 'connection', 'reset'])
            
            if is_net_err:
                # Backend network failure - DO NOT treat as SAFE (Evasion Vector)
                # Attackers could block our IP to force a network error and bypass the scan.
                # Fail-safe: mark as UNKNOWN/SUSPICIOUS.
                return {
                    "status": "ok",
                    "url": original_url,
                    "resolved_url": final_url,
                    "domain": extract_domain(original_url),
                    "risk_score": 50,
                    "verdict": "UNKNOWN",
                    "confidence": 0.4,
                    "evidence": [{
                        "signal": "url_shortener",
                        "evidence": f"Network error resolving short link (Possible Evasion): {error_msg}.",
                        "severity": "MEDIUM",
                        "weight": 50
                    }],
                    "engines": {
                        "url_unshortener": unshortener_result or {"status": "error"}
                    },
                    "analysis_date": timezone.now().isoformat() if django_available else datetime.datetime.now().isoformat()
                }
            else:
                # Dead link or malicious block - suspicious
                return {
                    "status": "ok",
                    "url": original_url,
                    "resolved_url": final_url,
                    "domain": extract_domain(original_url),
                    "risk_score": 50,
                    "verdict": "SUSPICIOUS",
                    "confidence": 0.4,
                    "evidence": [{
                        "signal": "url_shortener",
                        "evidence": f"Shortened URL could not be resolved: {error_msg}",
                        "severity": "MEDIUM",
                        "weight": 50
                    }],
                    "engines": {
                        "url_unshortener": unshortener_result or {"status": "error"}
                    },
                    "analysis_date": timezone.now().isoformat() if django_available else datetime.datetime.now().isoformat()
                }
            
        url = final_url
        
    except Exception as e:
        logger.warning(f"URL unshortener failed for {url}: {e}")
        unshortener_result = {"status": "error", "error": str(e), "details": {"was_shortened": False}}

    # ── PRE-PROCESSING: Open Redirect Detection ──────────────────────────
    try:
        redirect_target = _extract_open_redirect_target(url)
        if redirect_target:
            wrapper_domain = extract_domain(url)
            target_domain = extract_domain(redirect_target)
            if target_domain and target_domain != wrapper_domain:
                logger.info(f"Open Redirect detected: {wrapper_domain} → {target_domain}")
                open_redirect_result = {
                    "status": "ok",
                    "details": {
                        "is_open_redirect": True,
                        "wrapper_url": url,
                        "wrapper_domain": wrapper_domain,
                        "target_url": redirect_target,
                        "target_domain": target_domain,
                    }
                }
                url = redirect_target
    except Exception as e:
        logger.warning(f"Open redirect detection failed: {e}")

    domain = extract_domain(url)
    info = extract_domain_info(url)
    fqdn = info.get("fqdn") or domain
    root_domain = info.get("registrable_domain", "").lower()

    if not domain:
        return {
            "status": "error",
            "error": "Could not extract a valid domain or host from URL",
            "url": original_url,
            "resolved_url": url,
            "risk_score": 0,
            "verdict": "UNKNOWN",
            "analysis_date": timezone.now().isoformat() if django_available else datetime.datetime.now().isoformat()
        }

    # Cache by full URL (not just domain) to prevent path-level collisions.
    # e.g. evil.com/login and evil.com/about must NOT share cache entries.
    cache_key = f"domain_analysis:{hashlib.sha256(url.encode()).hexdigest()}"
    if use_cache and cache:
        cached_result = cache.get(cache_key)
        if cached_result:
            try:
                if isinstance(cached_result, str):
                    return json.loads(cached_result)
                return cached_result
            except Exception:
                pass

    # ── FAST-PATH: Global Master Whitelist Bypass ──────────────────────────
    from .constants import SHARED_HOSTING_PROVIDERS, COUNTRY_CODE_SLDS
    GENERIC_PROVIDERS = SHARED_HOSTING_PROVIDERS | COUNTRY_CODE_SLDS

    try:
        from .dataset_loader import SAFETY_WHITELIST
        is_provider = domain in GENERIC_PROVIDERS
        has_subdomain = bool(info.get("subdomain"))
        is_whitelisted = domain in SAFETY_WHITELIST and not (is_provider and has_subdomain)
        
        url_lower = url.lower()
        risky_keywords = [
            "download", "feed", "api", "raw", "login", "signin", 
            "auth", "verify", "account", "update", "free", "gift", 
            "malware", "test", "sample", "payload", "suspicious",
            ".exe", ".zip", ".msi", ".apk", ".sh", ".bat", "?hl="
        ]
        is_risky_context = any(k in url_lower for k in risky_keywords)

        if is_whitelisted and not is_risky_context:
            fast_path_result = {
                "url": original_url,
                "resolved_url": url,
                "domain": domain,
                "risk_score": 0,
                "verdict": "SAFE",
                # M#5 FIX: Always include confidence for API consistency.
                # A whitelisted domain has maximum confidence (1.0).
                "confidence": 1.0,
                "raw_score": 0,
                "component_scores": {},
                "status": "ok",
                "engines": {
                    "fast_path": {"status": "ok", "details": {"reason": "Found in Global Master Whitelist"}},
                    "url_unshortener": unshortener_result or {"status": "skipped"}
                },
                "analysis_date": timezone.now().isoformat() if django_available else datetime.datetime.now().isoformat()
            }
            if use_cache and cache:
                cache.set(cache_key, fast_path_result, timeout=86400)
            return fast_path_result
            
    except Exception as e:
        logger.warning(f"Fast-path bypass failed: {e}")
        is_whitelisted = False

    # ── PARALLEL EXECUTION OF ENGINES (Async I/O & Threaded CPU) ─────────
    # Clear CPU vs I/O separation. Heavy algorithms offloaded to threads.
    
    tasks = []
    
    # In lite_mode, skip slow network engines like domain_age and ssl
    if not lite_mode:
        # For shared hosting providers, check the root domain age instead of the subdomain.
        age_target = root_domain if root_domain in SHARED_HOSTING_PROVIDERS else domain
        tasks.extend([
            _run_engine_safe("domain_age", get_domain_age(age_target)),
            _run_engine_safe("ssl", execute_with_retry_and_timeout(
                "ssl", analyze_ssl, domain, max_retries=1, timeout=5.0
            )),
        ])

    # Fast network & CPU engines (run in both modes)
    tasks.extend([
        _run_engine_safe("dns", execute_with_retry_and_timeout(
            "dns", analyze_dns, domain, max_retries=1, timeout=2.0 if lite_mode else 4.0, circuit_breaker=DNS_CIRCUIT_BREAKER
        )),
        _run_engine_safe("typosquatting", run_cpu_bound(detect_typosquatting, fqdn)),
        _run_engine_safe("url_features", run_cpu_bound(analyze_url_structure, url)),
        _run_engine_safe("phishing_patterns", run_cpu_bound(detect_phishing_patterns, url)),
        _run_engine_safe("homoglyph", run_cpu_bound(detect_homoglyph_attack, domain)),
        _run_engine_safe("threat_intelligence", run_cpu_bound(check_openphish, url)),
    ])

    engine_results = {}
    
    # Wait for all engines concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for res in results:
        if isinstance(res, Exception):
            logger.error(f"Critical Task Gathering Error: {res}")
            continue
        
        name, result = res
        engine_results[name] = result

    # Include Pre-processing Engine Results
    if unshortener_result: engine_results["url_unshortener"] = unshortener_result
    if open_redirect_result: engine_results["open_redirect"] = open_redirect_result
    if 'is_whitelisted' in locals() and is_whitelisted:
        engine_results["trusted_source"] = {"status": "ok"}

    # Calculate final Risk Score and Verdict
    scoring_result = RiskScorer.calculate(engine_results, domain, url)

    final_output = {
        "url": original_url,
        "resolved_url": url,
        "domain": domain,
        "risk_score": scoring_result.get("risk_score", 0),
        "verdict": scoring_result.get("verdict", "UNKNOWN"),
        "confidence": scoring_result.get("confidence", 0.0),
        "evidence": scoring_result.get("evidence", []),
        "raw_score": scoring_result.get("raw_weighted", 0),
        "component_scores": scoring_result.get("component_scores", {}),
        "status": "ok",
        "engines": engine_results,
        "analysis_date": timezone.now().isoformat() if django_available else datetime.datetime.now().isoformat()
    }

    if use_cache and cache:
        try:
            cache.set(cache_key, final_output, timeout=86400)
        except Exception as e:
            logger.warning(f"Failed to cache result for {domain}: {e}")

    return final_output
