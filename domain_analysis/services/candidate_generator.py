import string
from typing import List, Set
from .trie_index import get_candidates

def generate_candidates(domain: str) -> List[str]:
    """
    Generates potential 'legit' candidates that the given domain might be squatting.
    Uses prefix/suffix search and common permutations.
    """
    if not domain:
        return []

    candidates: Set[str] = set()
    parts = domain.split(".")
    main_part = parts[0]
    
    # 1. Prefix/Suffix search (existing)
    if len(main_part) >= 3:
        prefix = main_part[:3]
        candidates.update(get_candidates(prefix))
        
        suffix = main_part[-3:]
        candidates.update(get_candidates(suffix))

    # 2. Character substitutions / Omissions (Simulated)
    # Since we have a 1M domain trie, we can't easily iterate all permutations.
    # Instead, we look for domains that are *already* in our 'legit' list.
    
    # Let's try to find domains that share a significant portion of the name
    if len(main_part) > 5:
        mid_prefix = main_part[:5]
        candidates.update(get_candidates(mid_prefix))

    # 3. Handle common typos (e.g. 'gogle' -> 'google')
    # This is handled by the similarity engine later, 
    # but we need to ensure the *correct* domain is in the candidates list.
    
    # Filter candidates to only include those with similar length
    # to avoid pulling too many irrelevant domains from the trie
    filtered = [
        c for c in candidates 
        if abs(len(c.split(".")[0]) - len(main_part)) <= 2
    ]

    return filtered