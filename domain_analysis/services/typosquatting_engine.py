"""
Typosquatting Detection Engine
──────────────────────────────
Detects domain name impersonation:
1. Bloom Filter → Trie → Levenshtein similarity pipeline
2. Brand containment check (e.g., "instagram-copyright.com")
3. Latin character manipulation (e.g., "rn" → "m", "cl" → "d")
"""

from typing import Dict, Any
from .bloom_filter import is_legit_domain
from .candidate_generator import generate_candidates
from .similarity_engine import compute_similarity


# ── Latin Character Manipulation Map ──────────────────────────────────────
# These substitutions make domains look identical at a glance. For example:
#   rnicrosoft.com  →  looks like  microsoft.com  (rn → m)
#   paypa1.com      →  looks like  paypal.com     (1 → l)
#   g00gle.com      →  looks like  google.com     (0 → o)
LATIN_TRICKS = {
    "rn": "m",   # rn looks like m
    "cl": "d",   # cl looks like d
    "vv": "w",   # vv looks like w
    "nn": "m",   # nn can look like m
    "1": "l",    # one looks like lowercase L
    "0": "o",    # zero looks like o
    "5": "s",    # 5 looks like S
    "!": "i",    # exclamation looks like i
}


def _normalize_latin_tricks(domain: str) -> str:
    """Normalize a domain by replacing Latin manipulation tricks."""
    normalized = domain.lower()
    for trick, real_char in LATIN_TRICKS.items():
        normalized = normalized.replace(trick, real_char)
    return normalized


def detect_typosquatting(domain: str) -> Dict[str, Any]:
    """
    Detects if the domain is a typosquatting attempt of a legitimate domain.
    """
    if not domain:
        return {
            "status": "error",
            "error": "No domain provided",
            "details": {"is_typosquatting": False}
        }

    try:
        from .dataset_loader import SAFETY_WHITELIST
        # Step 1: Check if it's already a known strictly safe domain
        if domain in SAFETY_WHITELIST:
            return {
                "status": "ok",
                "details": {
                    "is_typosquatting": False,
                    "reason": "Legitimate domain"
                }
            }

        # Step 2: Latin Character Manipulation Detection
        # Check if normalizing tricks produces a known legit domain
        main_part = domain.split(".")[0].lower()
        normalized = _normalize_latin_tricks(main_part)

        if normalized != main_part:
            # The domain contains trick characters — check if normalized is a brand
            for tld in [".com", ".org", ".net", ".io"]:
                if is_legit_domain(normalized + tld):
                    return {
                        "status": "ok",
                        "details": {
                            "is_typosquatting": True,
                            "latin_manipulation": True,
                            "target_domain": normalized + tld,
                            "original": domain,
                            "confidence": 0.95
                        }
                    }

        # Step 3: Generate potential candidates via Trie
        candidates = generate_candidates(domain)
        if candidates:
            # Step 4: Compute similarity
            similarity = compute_similarity(domain, candidates)
            if similarity:
                return {
                    "status": "ok",
                    "details": {
                        "is_typosquatting": True,
                        "target_domain": similarity["match"],
                        "confidence": similarity["confidence"],
                        "similarity_score": similarity["confidence"]
                    }
                }

        # Step 5: Brand Containment (Catch brand keywords in larger strings)
        # e.g., "instagram-copyright-infringement.com" contains "instagram"
        SENSITIVE_BRANDS = frozenset([
            # Social Media
            "instagram", "facebook", "whatsapp", "twitter", "tiktok",
            "discord", "telegram", "snapchat", "linkedin", "pinterest",
            # Tech Giants
            "microsoft", "apple", "google", "amazon", "netflix",
            "outlook", "onedrive", "office365", "office",
            # Finance & Crypto
            "paypal", "stripe", "binance", "coinbase", "metamask",
            "blockchain", "trustwallet", "ledger", "trezor", "phantom",
            "chase", "wellsfargo", "wells-fargo", "bankofamerica",
            "capitalone", "hsbc", "citibank", "barclays",
            # Cloud & Services
            "icloud", "dropbox", "salesforce", "adobe", "zoom",
            "slack", "shopify", "wordpress",
            # Gaming
            "steam", "steamcommunity", "roblox", "epicgames", "epic",
            # Delivery
            "fedex", "ups", "dhl", "usps",
            # AI
            "openai", "chatgpt",
        ])

        for brand in SENSITIVE_BRANDS:
            if brand in main_part and brand != main_part:
                return {
                    "status": "ok",
                    "details": {
                        "is_typosquatting": True,
                        "brand_impersonation": True,
                        "target_brand": brand,
                        "confidence": 0.85
                    }
                }

        # Step 6: Check if normalized domain matches brands
        # Catches "paypa1" (normalized to "paypal"), "g00gle" (normalized to "google")
        if normalized != main_part:
            for brand in SENSITIVE_BRANDS:
                if brand in normalized and brand != normalized:
                    return {
                        "status": "ok",
                        "details": {
                            "is_typosquatting": True,
                            "latin_manipulation": True,
                            "brand_impersonation": True,
                            "target_brand": brand,
                            "confidence": 0.90
                        }
                    }

        return {
            "status": "ok",
            "details": {
                "is_typosquatting": False
            }
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "details": {"is_typosquatting": False}
        }