"""
URL Unshortener Engine
─────────────────────
Detects and resolves shortened URLs using an Adaptive Multi-Layer Strategy
to bypass Bot Detection, WAF blocks, and DNS Manipulation.
"""

import aiohttp
import asyncio
import logging
import re
from typing import Dict, Any, List
from urllib.parse import urlparse
from builtins import Exception
from .async_utils import get_async_session, run_cpu_bound
from .dns_intelligence_engine import resolve_ip_custom

logger = logging.getLogger(__name__)

try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False
    logger.warning("curl_cffi not installed. Layer 2 & 3 Anti-Evasion will be disabled.")

# Known URL shortener domains
SHORTENER_DOMAINS = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "v.gd", "buff.ly", "rb.gy",
    "cutt.ly", "shorturl.at", "tiny.cc", "lnkd.in",
    "youtu.be", "amzn.to", "amzn.eu",
    "fb.me", "fb.watch", "wa.me", "t.me", "pin.it",
    "redd.it", "vk.cc", "x.co",
    "aka.ms", "apple.co", "spoti.fi", "hubs.ly",
    "mcaf.ee", "spr.ly", "ift.tt", "dlvr.it",
    "rebrand.ly", "bl.ink", "clk.sh", "snip.ly",
    "short.io", "t.ly", "s.id", "rotf.lol",
    "qr.ae", "adf.ly", "bc.vc", "j.mp",
    "soo.gd", "s.coop", "u.to", "shrtco.de",
    "trib.al", "shorturl.asia", "1url.com", "hyperurl.co",
})

_NOT_SHORTENERS = frozenset({
    "zoom.us", "ebay.com", "etsy.com", "uber.com", "lyft.com",
    "yelp.com", "imdb.com", "x.com", "slack.com", "visa.com",
    "dell.com", "xbox.com", "hulu.com", "roku.com", "wish.com",
    "nike.com", "ikea.com", "usps.com", "dhl.com", "ups.com",
    "bmw.com", "audi.com", "ford.com", "gap.com", "hp.com",
    "ibm.com", "sap.com", "box.com", "bbc.com", "cnn.com",
    "mit.edu", "who.int", "nih.gov", "irs.gov", "usa.gov",
    "go.dev", "npm.io", "pypi.org", "wix.com", "aws.com",
})

_SHORTENER_PATH_RE = re.compile(r"^[A-Za-z0-9_-]{1,10}$")

MAX_REDIRECTS = 10
HOP_TIMEOUT = 5.0

def is_shortened_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname: return False
        hostname = hostname.lower().strip(".")
        
        if hostname in SHORTENER_DOMAINS: return True
        
        parts = hostname.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in SHORTENER_DOMAINS: return True
        
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        if base_domain in _NOT_SHORTENERS or hostname in _NOT_SHORTENERS:
            return False
            
        domain_part = ".".join(parts[:-1]) if len(parts) > 1 else parts[0]
        path = parsed.path.strip("/")
        if (len(domain_part) <= 4 and 
            0 < len(path) <= 8 and 
            "/" not in path and
            _SHORTENER_PATH_RE.match(path) and
            not any(word in path.lower() for word in ["login", "signin", "account", "home", "about", "help", "feed", "mail", "inbox"])):
            return True
            
        return False
    except Exception:
        return False

def is_waf_block(status_code: int, headers: dict = None, text: str = "") -> bool:
    """Detects if a response is likely a WAF block."""
    if headers is None: headers = {}
    if status_code in [403, 429, 503]: return True
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    if "cf-ray" in headers_lower and status_code >= 400: return True
    server = headers_lower.get("server", "")
    if ("cloudflare" in server or "ddos-guard" in server or "akamai" in server) and status_code >= 400: return True
    if text and ("just a moment" in text.lower() or "security check" in text.lower() or "cloudflare" in text.lower()) and status_code >= 400: return True
    return False

# ─── Layer 2 & 3: Anti-Evasion Impersonation ────────────────────────────────
def _fetch_with_impersonation(url: str, ip: str = None, host: str = None, verify: bool = True) -> Dict[str, Any]:
    """Runs a curl_cffi request synchronously (called via run_cpu_bound)."""
    if not HAS_CURL_CFFI:
        return {"success": False, "error": "curl_cffi not installed"}
    
    kwargs = {
        "impersonate": "chrome120",
        "allow_redirects": True,
        "timeout": HOP_TIMEOUT * 2,
        "verify": verify
    }
    
    target_url = url
    if ip:
        parsed = urlparse(url)
        path_query = parsed.path
        if parsed.query: path_query += f"?{parsed.query}"
        if not path_query: path_query = "/"
        target_url = f"{parsed.scheme}://{ip}{path_query}"
        if not host: host = parsed.hostname
        kwargs["headers"] = {"Host": host}
        
    try:
        response = curl_requests.get(target_url, **kwargs)
        
        # Build redirect chain
        chain = []
        for i, r in enumerate(response.history):
            chain.append({"hop": i + 1, "url": r.url, "status_code": r.status_code})
        chain.append({"hop": len(chain) + 1, "url": response.url, "status_code": response.status_code})
        
        waf_blocked = is_waf_block(response.status_code, dict(response.headers), response.text)
        
        return {
            "success": not waf_blocked and response.status_code < 400,
            "waf_blocked": waf_blocked,
            "final_url": response.url,
            "redirect_chain": chain,
            "status_code": response.status_code
        }
    except Exception as e:
        return {"success": False, "error": str(e), "is_net_err": any(k in str(e).lower() for k in ['timeout', 'resolve', 'connection', 'reset', 'getaddrinfo'])}

# ─── Layer 1: Fast Path ───────────────────────────────────────────────────
async def _fetch_aiohttp(url: str) -> Dict[str, Any]:
    session = await get_async_session()
    redirect_chain = []
    current_url = url
    visited = set()
    
    try:
        for hop in range(MAX_REDIRECTS):
            if current_url in visited:
                break
            visited.add(current_url)
            # T9 FIX: Initialize text before the loop so it's always defined
            # even if the GET branch is never reached.
            text = ""

            try:
                async with session.head(current_url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=HOP_TIMEOUT), ssl=True) as response:
                    status_code = response.status
                    headers = response.headers
            except aiohttp.ClientSSLError:
                async with session.head(current_url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=HOP_TIMEOUT), ssl=False) as response:
                    status_code = response.status
                    headers = response.headers

            redirect_chain.append({"hop": hop + 1, "url": current_url, "status_code": status_code})

            if 300 <= status_code < 400:
                location = headers.get("Location")
                if not location: break
                if location.startswith("/"):
                    parsed = urlparse(current_url)
                    location = f"{parsed.scheme}://{parsed.netloc}{location}"
                elif not location.startswith("http"):
                    parsed = urlparse(current_url)
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/', 1)[0]}"
                    location = f"{base}/{location}"
                current_url = location
            else:
                break

        if not redirect_chain or redirect_chain[-1].get("status_code", 0) >= 400:
            current_url = url
            redirect_chain = []
            visited = set()
            for hop in range(MAX_REDIRECTS):
                if current_url in visited: break
                visited.add(current_url)
                
                try:
                    async with session.get(current_url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=HOP_TIMEOUT), ssl=True) as response:
                        status_code = response.status
                        headers = response.headers
                        text = await response.text()
                except aiohttp.ClientSSLError:
                    async with session.get(current_url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=HOP_TIMEOUT), ssl=False) as response:
                        status_code = response.status
                        headers = response.headers
                        text = await response.text()

                redirect_chain.append({"hop": hop + 1, "url": current_url, "status_code": status_code})

                if 300 <= status_code < 400:
                    location = headers.get("Location")
                    if not location: break
                    if location.startswith("/"):
                        parsed = urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    elif not location.startswith("http"):
                        parsed = urlparse(current_url)
                        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/', 1)[0]}"
                        location = f"{base}/{location}"
                    current_url = location
                else:
                    break

        waf_blocked = is_waf_block(redirect_chain[-1]["status_code"] if redirect_chain else 0, headers, text if 'text' in locals() else "")
        return {
            "success": not waf_blocked and (redirect_chain[-1]["status_code"] if redirect_chain else 0) < 400,
            "waf_blocked": waf_blocked,
            "final_url": current_url,
            "redirect_chain": redirect_chain
        }
    except asyncio.TimeoutError:
        return {"success": False, "error": "Timeout while following redirects", "waf_blocked": True, "redirect_chain": redirect_chain}
    except Exception as e:
        is_net_err = any(k in str(e).lower() for k in ['timeout', 'getaddrinfo', 'connection', 'reset'])
        return {"success": False, "error": str(e), "is_net_err": is_net_err, "redirect_chain": redirect_chain}


async def unshorten_url(url: str) -> Dict[str, Any]:
    if not url:
        return {"status": "error", "error": "No URL provided", "details": {"was_shortened": False}}

    shortened = is_shortened_url(url)
    if not shortened:
        return {
            "status": "ok",
            "details": {"was_shortened": False, "original_url": url, "final_url": url, "redirect_chain": [], "hop_count": 0}
        }

    # Layer 1: Fast Path (aiohttp)
    l1_res = await _fetch_aiohttp(url)
    if l1_res.get("success"):
        return {
            "status": "ok",
            "details": {
                "was_shortened": l1_res["final_url"] != url,
                "original_url": url,
                "final_url": l1_res["final_url"],
                "redirect_chain": l1_res["redirect_chain"],
                "hop_count": len(l1_res["redirect_chain"])
            }
        }

    # If curl_cffi is missing, fallback to L1 result
    if not HAS_CURL_CFFI:
        logger.warning(f"curl_cffi missing. Layer 1 failed for {url}. Returning fallback.")
        return _build_fallback_result(url, l1_res)

    # Trigger Evasion logic if L1 timed out, got connection error, or hit a WAF
    logger.info(f"[Evasion] Layer 1 failed for {url}. Triggering Layer 2: curl_cffi.")
    
    # Layer 2: Anti-Evasion Impersonation
    l2_res = await run_cpu_bound(_fetch_with_impersonation, url)
    if l2_res and l2_res.get("success"):
        return _build_success_result(url, l2_res)

    # Layer 3: Smart Custom DNS Override
    # Trigger if Layer 2 encountered a network resolution error
    if l2_res and (l2_res.get("is_net_err") or l2_res.get("waf_blocked")):
        logger.info(f"[Evasion] Layer 2 failed. Triggering Layer 3: DNS Override for {url}.")
        domain = urlparse(url).hostname
        ip = await resolve_ip_custom(domain)
        if ip:
            # Try with strict SSL first
            l3_res = await run_cpu_bound(_fetch_with_impersonation, url, ip=ip, host=domain, verify=True)
            if l3_res and l3_res.get("success"):
                return _build_success_result(url, l3_res)
            
            # Fallback to verify=False if strict SSL failed
            logger.info(f"[Evasion] Layer 3 Strict SSL failed. Falling back to verify=False.")
            l3_res_fallback = await run_cpu_bound(_fetch_with_impersonation, url, ip=ip, host=domain, verify=False)
            if l3_res_fallback and l3_res_fallback.get("success"):
                return _build_success_result(url, l3_res_fallback)

    # All layers failed, return best-effort fallback based on Layer 1/2 error
    return _build_fallback_result(url, l1_res)

def _build_success_result(original_url: str, res: dict) -> dict:
    return {
        "status": "ok",
        "details": {
            "was_shortened": res["final_url"] != original_url,
            "original_url": original_url,
            "final_url": res["final_url"],
            "redirect_chain": res["redirect_chain"],
            "hop_count": len(res["redirect_chain"])
        }
    }

def _build_fallback_result(original_url: str, res: dict) -> dict:
    error_msg = res.get("error", "Failed to resolve link")
    return {
        "status": "error",
        "error": error_msg,
        "details": {
            "was_shortened": True,
            "original_url": original_url,
            "final_url": res.get("final_url", original_url),
            "redirect_chain": res.get("redirect_chain", []),
            "hop_count": len(res.get("redirect_chain", []))
        }
    }
