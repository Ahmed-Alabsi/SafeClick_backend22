"""
Phishing Pattern Engine
───────────────────────
Detects known phishing keywords and compound suspicious patterns in URLs.

Features:
1. Single-keyword search (60+ terms)
2. Compound pattern detection ("secure-login", "verify-account", etc.)
3. Suspicious TLD detection (.xyz, .top, .info, .online, etc.)
"""

from typing import Dict, Any, List

from .bloom_filter import is_legit_domain
from .domain_utils import extract_domain

from difflib import SequenceMatcher

# Hard whitelist for critical infrastructure domains that are often 
# used for redirection but are inherently safe as root domains.
HARD_WHITELIST = frozenset(["t.me", "wa.me", "telegram.me", "bit.ly", "tinyurl.com"])

PHISHING_KEYWORDS = frozenset([
    "login", "signin", "logon", "auth", "password", "credential",
    "verify", "verification", "confirm", "validate", "secure", "security",
    "account", "update", "recover", "reset", "unlock", "activate",
    "suspend", "blocked", "restrict", "disable", "expire",
    "billing", "payment", "invoice", "refund", "tax", "purchase",
    "banking", "transaction", "wire", "transfer",
    "wallet", "seed", "phrase", "claim", "reward", "bonus",
    "gift", "free", "premium", "win", "prize", "offer",
    "urgent", "required", "immediately", "alert", "warning", "action",
    "support", "service", "customer", "helpdesk", "admin",
    "portal", "webmail", "online", "access", "entry",
    "drive", "shared", "document", "file", "download", "view",
    "blockchain", "metamask", "ledger", "trust", "nitro",
    "discord", "telegram", "steam", "official", "community", "member",
    "cracked", "crack", "keygen", "patch", "activator",
    "antivirus", "scan", "detected", "infected",
    "storage", "full", "upgrade", "capacity", "quota",
])

BRAND_LURES = frozenset([
    "paypal", "microsoft", "google", "apple", "facebook", "instagram", 
    "twitter", "amazon", "netflix", "spotify", "linkedin", "steam",
    "whatsapp", "telegram", "discord", "binance", "coinbase", "metamask",
    "outlook", "office365", "outlook365", "icloud", "itunes"
])

COMPOUND_PATTERNS = frozenset([
    "secure-login", "login-secure", "verify-account", "account-verify",
    "update-account", "account-update", "confirm-identity", "verify-identity",
    "reset-password", "password-reset", "security-check", "security-alert",
    "account-blocked", "account-suspended", "tax-refund", "claim-refund",
    "free-gift", "gift-card", "gift-claim", "seed-phrase", "wallet-recovery",
    "copyright-infringement", "meeting-invite", "package-delivery",
    "delivery-update", "tracking-confirm", "action-required",
])

SUSPICIOUS_TLDS = frozenset([
    ".xyz", ".top", ".info", ".online", ".site", ".club",
    ".live", ".click", ".icu", ".buzz", ".fun", ".work",
    ".monster", ".tk", ".ml", ".ga", ".cf", ".gq",
])

def _is_fuzzy_match(word: str, target: str, threshold: float = 0.8) -> bool:
    """Checks if word is a fuzzy match for target (leet-speak or typos)."""
    # Quick Check: Literal substring
    if target in word:
        return True
    
    # Fuzzy Check: Sequence similarity
    # We check substrings of the word that match the target length
    if len(word) < len(target):
        return False
        
    for i in range(len(word) - len(target) + 1):
        sub = word[i:i+len(target)]
        if SequenceMatcher(None, sub, target).ratio() >= threshold:
            return True
    return False

def detect_phishing_patterns(url: str) -> Dict[str, Any]:
    """
    Detects phishing keywords, compound patterns, and fuzzy brand impersonation.
    """
    if not url:
        return {"status": "error", "error": "No URL provided", "details": {"keyword_count": 0}}

    try:
        from urllib.parse import unquote
        url_lower = unquote(url).lower()
        domain = extract_domain(url_lower)
        
        # 0. Hard Whitelist check
        if domain in HARD_WHITELIST:
            return {
                "status": "ok",
                "details": {
                    "keyword_count": 0, "keywords": [], "compound_patterns": [],
                    "suspicious_tld": False, "impersonated_brands": [],
                    "is_brand_spoof": False, "is_suspicious": False, "fast_path": True
                }
            }
        
        # 1. Single keyword matches
        keyword_matches = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]

        # 2. Compound pattern matches
        compound_matches = [p for p in COMPOUND_PATTERNS if p in url_lower]

        # 3. Suspicious TLD check
        has_suspicious_tld = any(url_lower.endswith(tld) for tld in SUSPICIOUS_TLDS)

        # 4. Fuzzy Brand Impersonation Check (BRAND SHIELD)
        impersonated_brands = []
        is_legit = is_legit_domain(domain)
        
        if not is_legit:
            for brand in BRAND_LURES:
                if _is_fuzzy_match(domain, brand, threshold=0.8):
                    impersonated_brands.append(brand)

        total_count = len(keyword_matches) + len(compound_matches)
        is_impersonation = len(impersonated_brands) > 0

        return {
            "status": "ok",
            "details": {
                "keyword_count": total_count,
                # M#6 FIX: Keep keyword_matches and impersonated_brands separate.
                # Brand names ("paypal") are NOT phishing keywords ("login") — mixing
                # them confused consumers of this engine's output.
                "keywords": sorted(set(keyword_matches)),
                "compound_patterns": sorted(compound_matches),
                "suspicious_tld": has_suspicious_tld,
                "impersonated_brands": impersonated_brands,
                "is_brand_spoof": is_impersonation,
                "is_suspicious": total_count > 0 or has_suspicious_tld or is_impersonation
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "details": {"keyword_count": 0}
        }