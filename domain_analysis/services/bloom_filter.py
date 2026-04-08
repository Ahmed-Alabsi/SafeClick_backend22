"""
Bloom Filter — Whitelist Index
──────────────────────────────
Provides O(1) probabilistic lookups for legitimate domain verification.

Design Decision:
    Use dynamic capacity based on actual dataset size rather than a hardcoded
    100K limit. This ensures ALL domains from the master whitelist are indexed,
    not just the first 100K out of 17.5M.
"""

from pybloom_live import BloomFilter
from .dataset_loader import load_domains
import threading
import logging

logger = logging.getLogger(__name__)

_bloom_instance = None
_lock = threading.Lock()


def build_bloom():
    """Initializes and returns a Bloom Filter with ALL legitimate domains."""
    domains = load_domains()
    count = len(domains) if domains else 100000

    # Use actual dataset size for capacity to avoid false negatives from truncation
    bf = BloomFilter(capacity=max(count, 100000), error_rate=0.001)

    loaded = 0
    for d in domains:
        if d:
            bf.add(d)
            loaded += 1

    logger.info(f"Bloom Filter built: {loaded} domains loaded (capacity={count})")
    return bf


def get_bloom():
    """Thread-safe singleton getter for the Bloom Filter."""
    global _bloom_instance
    if _bloom_instance is None:
        with _lock:
            if _bloom_instance is None:
                _bloom_instance = build_bloom()
    return _bloom_instance


def is_legit_domain(domain: str) -> bool:
    """Checks if a domain is in the legitimate domains list."""
    if not domain:
        return False

    bloom = get_bloom()
    if bloom is None:
        return False

    return domain in bloom