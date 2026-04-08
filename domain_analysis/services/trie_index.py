import marisa_trie
from .dataset_loader import load_domains
import threading

_trie_instance = None
_lock = threading.Lock()

def build_trie():
    """Initializes and returns a Trie with legitimate domains."""
    domains = load_domains()
    return marisa_trie.Trie(domains)

def get_trie():
    """Thread-safe singleton getter for the Trie."""
    global _trie_instance
    if _trie_instance is None:
        with _lock:
            if _trie_instance is None:
                _trie_instance = build_trie()
    return _trie_instance

def get_candidates(prefix):
    """Returns all keys in the trie starting with the given prefix."""
    t = get_trie()
    if t is None:
        return []
    try:
        return t.keys(prefix)
    except:
        return []