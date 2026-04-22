"""
Trie Index (v4.1 - Memory Optimized)
─────────────────────────────────────
Provides fast prefix search for candidate generation in Typosquatting detection.
Indexes the Top 1M domains to maintain sub-second response times and stable memory.
"""

import marisa_trie
import threading
import logging
from .dataset_loader import load_ranked_domains

logger = logging.getLogger(__name__)

_trie_instance = None
_lock = threading.Lock()

def build_trie():
    """Initializes a Trie with Top 1M legitimate domains for efficient search."""
    logger.info("Building Trie Index for candidate generation...")
    domains = load_ranked_domains(limit=1000000)
    return marisa_trie.Trie(domains)

def get_trie():
    """Thread-safe singleton getter."""
    global _trie_instance
    if _trie_instance is None:
        with _lock:
            if _trie_instance is None:
                _trie_instance = build_trie()
    return _trie_instance

def get_candidates(prefix: str):
    """Returns all keys in the trie starting with the given prefix."""
    if not prefix: return []
    t = get_trie()
    try:
        return t.keys(prefix)
    except Exception as e:
        logger.error(f"Trie search failed for prefix '{prefix}': {e}")
        return []