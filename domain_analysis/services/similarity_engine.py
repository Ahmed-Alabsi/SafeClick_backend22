from rapidfuzz import fuzz
from typing import Dict, Any, List, Optional

SIMILARITY_THRESHOLD = 80

def compute_similarity(domain: str, candidates: List[str]) -> Optional[Dict[str, Any]]:
    """
    Computes similarity between the domain and a list of legitimate candidates.
    Returns the best match if above threshold.
    """
    if not domain or not candidates:
        return None

    best_match = None
    max_score = 0
    
    # We compare only the main domain part to avoid TLD noise
    domain_main = domain.split(".")[0]

    for legit in candidates:
        legit_main = legit.split(".")[0]
        
        # Ratio: Levenshtein distance based similarity
        score = fuzz.ratio(domain_main, legit_main)
        
        # Partial Ratio: Useful for 'google-login.com' matching 'google.com'
        partial_score = fuzz.partial_ratio(domain_main, legit_main)
        
        # Combined confidence
        confidence = (score * 0.7) + (partial_score * 0.3)
        
        if confidence > max_score:
            max_score = confidence
            best_match = legit

    if max_score >= SIMILARITY_THRESHOLD:
        return {
            "match": best_match,
            "confidence": round(max_score, 2),
            "method": "levenshtein_combined"
        }

    return None