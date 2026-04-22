"""
Bloom Filter (v4.1 - Memory Efficient)
──────────────────────────────────────
Provides O(1) probabilistic lookups for legitimate domain verification.
Uses streaming to load 17M+ domains without exhausting RAM.
"""

from pybloom_live import BloomFilter
from .dataset_loader import stream_domains
import threading
import logging

logger = logging.getLogger(__name__)

_bloom_instance = None
_lock = threading.Lock()

# Safe capacity for 17.4M master whitelist
BLOOM_CAPACITY = 20000000
ERROR_RATE = 0.001

def build_bloom():
    """Builds the Bloom Filter by streaming domains from disk."""
    logger.info(f"Building Bloom Filter (Streaming mode, capacity={BLOOM_CAPACITY})...")
    bf = BloomFilter(capacity=BLOOM_CAPACITY, error_rate=ERROR_RATE)

    loaded = 0
    for domain in stream_domains():
        bf.add(domain)
        loaded += 1
        if loaded % 1000000 == 0:
            logger.debug(f"Bloom loading progress: {loaded} domains...")

    logger.info(f"Bloom Filter initialized: {loaded} domains verified and indexed.")
    return bf

def get_bloom():
    """Thread-safe singleton getter."""
    global _bloom_instance
    if _bloom_instance is None:
        with _lock:
            if _bloom_instance is None:
                _bloom_instance = build_bloom()
    return _bloom_instance

def is_legit_domain(domain: str) -> bool:
    """Checks if a domain is in the legitimate domains list."""
    if not domain: return False
    bloom = get_bloom()
    return domain in bloom