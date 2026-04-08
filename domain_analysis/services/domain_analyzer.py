import logging
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any

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

from .domain_utils import extract_domain
from .domain_age import get_domain_age
from .typosquatting_engine import detect_typosquatting
from .url_feature_engine import analyze_url_structure
from .phishing_pattern_engine import detect_phishing_patterns
from .homoglyph_engine import detect_homoglyph_attack
from .dns_intelligence_engine import analyze_dns
from .ssl_intelligence_engine import analyze_ssl
from .threat_intelligence import check_openphish
from .url_unshortener_engine import unshorten_url
from .risk_scoring import RiskScorer
from .bloom_filter import get_bloom

logger = logging.getLogger(__name__)

# Bounded executor: 8 engines × 3 concurrent users = 24 threads max
# Avoids excessive thread spawning and OS-level resource exhaustion
_ANALYSIS_EXECUTOR = ThreadPoolExecutor(max_workers=24)

# Warm-up: Initialize Bloom Filter and Trie on module load
try:
    from .trie_index import get_trie
    get_bloom()
    get_trie()
except Exception as e:
    logger.error(f"Initialization warm-up failed: {e}")


def run_engine_safe(name: str, func, *args) -> Dict[str, Any]:
    """Wraps an engine call to ensure isolated execution with no information leakage."""
    try:
        return func(*args)
    except Exception as e:
        logger.error(f"Engine {name} failed: {str(e)}", exc_info=True)
        return {
            "status": "error",
            "error": f"Engine {name} encountered an internal error",
            "details": {}
        }


def analyze_domain(url: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Orchestrates the domain analysis process with parallel engines, isolation, and caching.
    Now includes URL unshortening as a pre-processing step.
    """

    # ── PRE-PROCESSING: URL Unshortening ─────────────────────────────────
    unshortener_result = None
    
    # Ensure scheme exists for proper URL parsing, default to http://
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    original_url = url
    try:
        from .url_unshortener_engine import is_shortened_url
        was_shortener = is_shortened_url(url)
        
        unshortener_result = unshorten_url(url)
        
        # Determine the final URL after following redirects
        final_url = url
        if unshortener_result.get("status") == "ok":
            resolved = unshortener_result.get("details", {}).get("final_url")
            if resolved and resolved != url:
                final_url = resolved
        
        # CRITICAL FIX: If it was a shortener, but we failed to resolve a real destination,
        # we MUST abort. Analyzing 'bit.ly' or 'tinyurl.com' itself leads to 100% false positives
        # because the domain is just an infrastructure provider.
        if was_shortener and is_shortened_url(final_url):
            error_msg = unshortener_result.get("error", "Unable to resolve short link destination (Network Error or Dead Link)")
            return {
                "status": "error",
                "error": f"Shortened URL resolution failed: {error_msg}",
                "url": original_url,
                "resolved_url": final_url,
                "domain": extract_domain(original_url),
                "risk_score": 0,
                "verdict": "ERROR",
                "analysis_date": timezone.now().isoformat() if django_available else datetime.datetime.now().isoformat()
            }
            
        url = final_url  # Use resolved URL for all downstream analysis
        
    except Exception as e:
        logger.warning(f"URL unshortener failed for {url}: {e}")
        unshortener_result = {"status": "error", "error": str(e), "details": {"was_shortened": False}}

    domain = extract_domain(url)

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

    # ── Redis Caching Layer ────────────────────────────────────────────────
    cache_key = f"domain_analysis:{hashlib.sha256(domain.encode()).hexdigest()}"
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
    GENERIC_PROVIDERS = {
        "us.com", "uk.com", "eu.com", "de.com", "jp.net", "ru.com", "ae.org", "hu.com", "kr.com", "qc.com", "uy.com",
        "za.com", "br.com", "cn.com", "sa.com", "se.com", "se.net", "uk.net", "gb.com", "gb.net", "no.com", "hu.net",
        "jpn.com", "gr.com", "co.com", "github.io", "vercel.app", "netlify.app", "herokuapp.com", "firebaseapp.com",
        "duckdns.org", "ngrok.io", "bit.ly", "tinyurl.com", "s3.amazonaws.com", "blob.core.windows.net", "web.app",
        "s3.platform.com", "pages.dev", "azurewebsites.net"
    }

    try:
        from .dataset_loader import SAFETY_WHITELIST
        from .domain_utils import extract_domain_info
        info = extract_domain_info(url)
        is_provider = domain in GENERIC_PROVIDERS
        has_subdomain = bool(info.get("subdomain"))

        # ONLY fast-path if it's strictly in the curated SAFETY_WHITELIST
        if domain in SAFETY_WHITELIST and not (is_provider and has_subdomain):
            fast_path_result = {
                "url": original_url,
                "resolved_url": url,
                "domain": domain,
                "risk_score": 0,
                "verdict": "SAFE",
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

    # Define tasks for parallel execution (name, function, *args)
    tasks = [
        ("domain_age", get_domain_age, domain),
        ("typosquatting", detect_typosquatting, domain),
        ("url_features", analyze_url_structure, url),
        ("phishing_patterns", detect_phishing_patterns, url),
        ("homoglyph", detect_homoglyph_attack, domain),
        ("dns", analyze_dns, domain),
        ("ssl", analyze_ssl, domain),
        ("threat_intelligence", check_openphish, url),
    ]

    engine_results = {}
    total_timeout = 12.0  # Generous timeout for network engines

    # Use the persistent global executor
    future_to_engine = {}
    for task_tuple in tasks:
        name = task_tuple[0]
        func = task_tuple[1]
        args = task_tuple[2:]
        future = _ANALYSIS_EXECUTOR.submit(run_engine_safe, name, func, *args)
        future_to_engine[future] = name

    # Wait for all with a strict timeout
    try:
        for future in as_completed(future_to_engine, timeout=total_timeout):
            engine_name = future_to_engine[future]
            try:
                result = future.result()
                engine_results[engine_name] = result
            except Exception as e:
                logger.error(f"Engine {engine_name} failed: {e}")
                engine_results[engine_name] = {"status": "error", "error": "Internal Error"}
    except TimeoutError:
        logger.warning(f"Analysis for {domain} partially timed out after {total_timeout}s")

    # Ensure all engines have a result entry (mark timed-out ones)
    for task_tuple in tasks:
        name = task_tuple[0]
        if name not in engine_results:
            engine_results[name] = {"status": "error", "error": "Timeout"}

    # Include URL unshortener result
    if unshortener_result:
        engine_results["url_unshortener"] = unshortener_result

    # Calculate final Risk Score and Verdict
    scoring_result = RiskScorer.calculate(engine_results)

    final_output = {
        "url": original_url,
        "resolved_url": url,
        "domain": domain,
        "risk_score": scoring_result.get("risk_score", 0),
        "verdict": scoring_result.get("verdict", "UNKNOWN"),
        "raw_score": scoring_result.get("raw_score", 0),
        "component_scores": scoring_result.get("component_scores", {}),
        "status": "ok",
        "engines": engine_results,
        "analysis_date": timezone.now().isoformat() if django_available else datetime.datetime.now().isoformat()
    }

    # Cache the result for 24 hours
    if use_cache and cache:
        try:
            cache.set(cache_key, final_output, timeout=86400)
        except Exception as e:
            logger.warning(f"Failed to cache result for {domain}: {e}")

    return final_output
