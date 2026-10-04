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

from pathlib import Path

# Safe capacity for 17.4M master whitelist
BLOOM_CAPACITY = 20000000
ERROR_RATE = 0.001
BLOOM_CACHE_PATH = Path(__file__).resolve().parent.parent / "master_whitelist_clean.bloom"

def build_bloom():
    """Loads Bloom Filter from binary cache if available, or streams from disk and caches."""
    if BLOOM_CACHE_PATH.exists():
        try:
            import pickle
            logger.info(f"Loading Bloom Filter from pre-compiled binary dump: {BLOOM_CACHE_PATH}")
            with open(BLOOM_CACHE_PATH, "rb") as f:
                bf = pickle.load(f)
            logger.info("Bloom Filter loaded instantly from binary cache.")
            return bf
        except Exception as e:
            logger.warning(f"Failed to load binary bloom cache: {e}. Rebuilding from dataset...")

    logger.info(f"Building Bloom Filter (Streaming mode, capacity={BLOOM_CAPACITY})...")
    bf = BloomFilter(capacity=BLOOM_CAPACITY, error_rate=ERROR_RATE)

    # 1. Always seed the verified SAFETY_WHITELIST and Brand Catalog domains
    from .dataset_loader import SAFETY_WHITELIST
    loaded = 0
    for d in SAFETY_WHITELIST:
        bf.add(d.lower())
        loaded += 1

    try:
        from apps.domains.services.brand_service import BrandService
        cat = BrandService.get_catalog()
        for d in cat.get("official_domains", set()):
            bf.add(d.lower())
            loaded += 1
    except Exception:
        pass

    # 2. Stream additional domains from CSV if available
    for domain in stream_domains():
        bf.add(domain)
        loaded += 1
        if loaded % 2000000 == 0:
            logger.debug(f"Bloom loading progress: {loaded} domains...")

    logger.info(f"Bloom Filter initialized: {loaded} domains verified and indexed.")

    # Save to binary cache for instant subsequent boots (only if loaded valid count)
    if loaded > 1000:
        try:
            import pickle
            logger.info(f"Saving compiled Bloom Filter binary to: {BLOOM_CACHE_PATH}")
            with open(BLOOM_CACHE_PATH, "wb") as f:
                pickle.dump(bf, f, protocol=pickle.HIGHEST_PROTOCOL)
            logger.info("Bloom Filter binary cache saved successfully.")
        except Exception as e:
            logger.warning(f"Could not persist bloom binary cache: {e}")

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
    """
    Checks if a domain is in the legitimate domains list.
    Fast-paths against in-memory SAFETY_WHITELIST and BrandService catalog
    before consulting the probabilistic Bloom Filter.
    """
    if not domain:
        return False
    d = domain.strip().lower()

    # Fast-path L1: In-memory verified set
    from .dataset_loader import SAFETY_WHITELIST
    if d in SAFETY_WHITELIST:
        return True

    # Fast-path L2: Brand Catalog official domains
    try:
        from apps.domains.services.brand_service import BrandService
        if BrandService.is_verified_official_domain(d):
            return True
    except Exception:
        pass

    # L3: Bloom Filter probabilistic lookup
    bloom = get_bloom()
    return d in bloom