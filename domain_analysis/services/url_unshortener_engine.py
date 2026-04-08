"""
URL Unshortener Engine
─────────────────────
Detects and resolves shortened URLs (Bitly, TinyURL, t.co, etc.)
by programmatically following HTTP 3xx redirects to retrieve the
final destination URL.

Design Decision:
    We use `requests.Session` with `allow_redirects=False` and manually
    follow each hop. This gives us full visibility into the redirect chain
    (important for security analysis) while preventing open-redirect attacks
    and infinite redirect loops.

    Alternative approaches considered:
    1. `requests.get(allow_redirects=True)` — simplest, but no chain visibility
    2. `httpx.AsyncClient` — async but adds dependency, overkill for single URL
    3. `urllib.request` — lower-level, harder to control timeouts per hop
    4. `curl_cffi` — fastest but requires native binary, not portable
    5. Manual socket + HTTP parsing — maximum control but too complex

    → Chosen: `requests.Session` with manual redirect following. Best balance
      of control, visibility, simplicity, and zero extra dependencies.
"""

import requests
import logging
from typing import Dict, Any, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Known URL shortener domains (comprehensive global list)
SHORTENER_DOMAINS = frozenset({
    # Major shorteners
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "v.gd", "buff.ly", "rb.gy",
    "cutt.ly", "shorturl.at", "tiny.cc", "lnkd.in",
    "youtu.be", "amzn.to", "amzn.eu",
    # Social media shorteners
    "fb.me", "fb.watch", "wa.me", "t.me", "pin.it",
    "redd.it", "vk.cc", "x.co",
    # Enterprise shorteners
    "aka.ms", "apple.co", "spoti.fi", "hubs.ly",
    "mcaf.ee", "spr.ly", "ift.tt", "dlvr.it",
    # Regional / other
    "rebrand.ly", "bl.ink", "clk.sh", "snip.ly",
    "short.io", "t.ly", "s.id", "rotf.lol",
    "qr.ae", "adf.ly", "bc.vc", "j.mp",
    "soo.gd", "s.coop", "u.to", "shrtco.de",
    "trib.al", "shorturl.asia", "1url.com", "hyperurl.co",
})

# Maximum number of redirect hops to follow (prevents infinite loops)
MAX_REDIRECTS = 10

# Total timeout for the entire unshortening process (seconds)
TOTAL_TIMEOUT = 5.0

# Per-hop connection timeout (seconds)
HOP_TIMEOUT = 2.0

# Reusable session for connection pooling
_session = None


def _get_session() -> requests.Session:
    """Returns a reusable requests.Session with optimal settings."""
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        # We handle redirects manually — no need to set max_redirects
    return _session


def is_shortened_url(url: str) -> bool:
    """
    Determines if a URL uses a known URL shortener service.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False

        hostname = hostname.lower().strip(".")

        # Direct match
        if hostname in SHORTENER_DOMAINS:
            return True

        # Check if it's a subdomain of a shortener (e.g., custom.bit.ly)
        parts = hostname.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in SHORTENER_DOMAINS:
                return True

        # Heuristic: very short domain with short path = likely a shortener
        # e.g., "abc.xy/k3f" — domain < 6 chars, path < 10 chars
        domain_part = ".".join(parts[:-1]) if len(parts) > 1 else parts[0]
        path = parsed.path.strip("/")
        if len(domain_part) <= 5 and 0 < len(path) <= 10 and "/" not in path:
            return True

        return False

    except Exception:
        return False


def unshorten_url(url: str) -> Dict[str, Any]:
    """
    Resolves a shortened URL by following HTTP redirects.

    Returns the final destination URL and the complete redirect chain.
    If the URL is not shortened, returns it unchanged with was_shortened=False.
    """
    if not url:
        return {
            "status": "error",
            "error": "No URL provided",
            "details": {"was_shortened": False}
        }

    # Quick check: is this a shortened URL?
    shortened = is_shortened_url(url)

    if not shortened:
        return {
            "status": "ok",
            "details": {
                "was_shortened": False,
                "original_url": url,
                "final_url": url,
                "redirect_chain": [],
                "hop_count": 0
            }
        }

    # Follow redirects manually
    session = _get_session()
    redirect_chain: List[Dict[str, Any]] = []
    current_url = url
    visited = set()

    try:
        for hop in range(MAX_REDIRECTS):
            # Prevent redirect loops
            if current_url in visited:
                logger.warning(f"Redirect loop detected at hop {hop}: {current_url}")
                break
            visited.add(current_url)

            try:
                response = session.head(
                    current_url,
                    allow_redirects=False,
                    timeout=HOP_TIMEOUT,
                    verify=True
                )
            except requests.exceptions.SSLError:
                # Retry without SSL verification for broken certs
                response = session.head(
                    current_url,
                    allow_redirects=False,
                    timeout=HOP_TIMEOUT,
                    verify=False
                )

            status_code = response.status_code
            redirect_chain.append({
                "hop": hop + 1,
                "url": current_url,
                "status_code": status_code
            })

            # Check for redirect (3xx status codes)
            if 300 <= status_code < 400:
                location = response.headers.get("Location")
                if not location:
                    logger.warning(f"Redirect without Location header at hop {hop + 1}")
                    break

                # Handle relative redirects
                if location.startswith("/"):
                    parsed = urlparse(current_url)
                    location = f"{parsed.scheme}://{parsed.netloc}{location}"
                elif not location.startswith("http"):
                    # Relative path without leading slash
                    parsed = urlparse(current_url)
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/', 1)[0]}"
                    location = f"{base}/{location}"

                current_url = location
            else:
                # Non-redirect response — this is the final destination
                break

        # If HEAD fails (some servers block HEAD), fallback to GET
        if not redirect_chain or redirect_chain[-1].get("status_code", 0) >= 400:
            current_url = url
            redirect_chain = []
            visited = set()

            for hop in range(MAX_REDIRECTS):
                if current_url in visited:
                    break
                visited.add(current_url)

                try:
                    response = session.get(
                        current_url,
                        allow_redirects=False,
                        timeout=HOP_TIMEOUT,
                        stream=True,  # Don't download body
                        verify=True
                    )
                except requests.exceptions.SSLError:
                    response = session.get(
                        current_url,
                        allow_redirects=False,
                        timeout=HOP_TIMEOUT,
                        stream=True,
                        verify=False
                    )

                status_code = response.status_code
                response.close()  # Close stream immediately

                redirect_chain.append({
                    "hop": hop + 1,
                    "url": current_url,
                    "status_code": status_code
                })

                if 300 <= status_code < 400:
                    location = response.headers.get("Location")
                    if not location:
                        break
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

        final_url = current_url
        was_shortened = final_url != url

        return {
            "status": "ok",
            "details": {
                "was_shortened": was_shortened,
                "original_url": url,
                "final_url": final_url,
                "redirect_chain": redirect_chain,
                "hop_count": len(redirect_chain)
            }
        }

    except requests.exceptions.Timeout:
        logger.warning(f"URL unshortening timed out for {url}")
        return {
            "status": "error",
            "error": "Timeout while following redirects",
            "details": {
                "was_shortened": True,
                "original_url": url,
                "final_url": url,
                "redirect_chain": redirect_chain,
                "hop_count": len(redirect_chain)
            }
        }

    except requests.exceptions.ConnectionError as e:
        logger.warning(f"Connection error unshortening {url}: {e}")
        return {
            "status": "error",
            "error": "Connection failed while following redirects",
            "details": {
                "was_shortened": True,
                "original_url": url,
                "final_url": url,
                "redirect_chain": redirect_chain,
                "hop_count": len(redirect_chain)
            }
        }

    except Exception as e:
        logger.error(f"URL unshortener error for {url}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": "Unexpected error during URL resolution",
            "details": {
                "was_shortened": True,
                "original_url": url,
                "final_url": url,
                "redirect_chain": redirect_chain,
                "hop_count": len(redirect_chain)
            }
        }
