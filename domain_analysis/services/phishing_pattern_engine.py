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

PHISHING_KEYWORDS = frozenset([
    # Authentication
    "login", "signin", "logon", "auth", "password", "credential",
    # Verification & Security
    "verify", "verification", "confirm", "validate", "secure", "security",
    # Account Actions
    "account", "update", "recover", "reset", "unlock", "activate",
    "suspend", "blocked", "restrict", "disable", "expire",
    # Financial
    "billing", "payment", "invoice", "refund", "tax", "purchase",
    "banking", "transaction", "wire", "transfer",
    # Lures
    "wallet", "seed", "phrase", "claim", "reward", "bonus",
    "gift", "free", "premium", "win", "prize", "offer",
    # Urgency
    "urgent", "required", "immediately", "alert", "warning", "action",
    # Services
    "support", "service", "customer", "helpdesk", "admin",
    "portal", "webmail", "online", "access", "entry",
    # Documents & Sharing
    "drive", "shared", "document", "file", "download", "view",
    # Brand-adjacent
    "blockchain", "metamask", "ledger", "trust", "nitro",
    "discord", "telegram", "steam", "official", "community", "member",
    # Malware lures
    "cracked", "crack", "keygen", "patch", "activator",
    "antivirus", "scan", "detected", "infected",
    # Storage
    "storage", "full", "upgrade", "capacity", "quota",
])

# Compound suspicious patterns — two-word combinations that are
# extremely common in phishing but rare in legitimate domains
COMPOUND_PATTERNS = frozenset([
    "secure-login", "login-secure", "verify-account", "account-verify",
    "update-account", "account-update", "confirm-identity", "verify-identity",
    "reset-password", "password-reset", "security-check", "security-alert",
    "account-blocked", "account-suspended", "tax-refund", "claim-refund",
    "free-gift", "gift-card", "gift-claim", "seed-phrase", "wallet-recovery",
    "copyright-infringement", "meeting-invite", "package-delivery",
    "delivery-update", "tracking-confirm", "action-required",
])

# Suspicious TLDs that are disproportionately used in phishing
SUSPICIOUS_TLDS = frozenset([
    ".xyz", ".top", ".info", ".online", ".site", ".club",
    ".live", ".click", ".icu", ".buzz", ".fun", ".work",
    ".monster", ".tk", ".ml", ".ga", ".cf", ".gq",
])


def detect_phishing_patterns(url: str) -> Dict[str, Any]:
    """
    Detects known phishing keywords, compound patterns, and suspicious TLDs.
    """
    if not url:
        return {
            "status": "error",
            "error": "No URL provided",
            "details": {"keyword_count": 0}
        }

    try:
        url_lower = url.lower()

        # 1. Single keyword matches
        keyword_matches = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]

        # 2. Compound pattern matches (high-confidence phishing indicators)
        compound_matches = [p for p in COMPOUND_PATTERNS if p in url_lower]

        # 3. Suspicious TLD check
        has_suspicious_tld = any(url_lower.endswith(tld) for tld in SUSPICIOUS_TLDS)

        # Total keyword count includes compound patterns as bonus
        total_count = len(keyword_matches) + len(compound_matches)

        return {
            "status": "ok",
            "details": {
                "keyword_count": total_count,
                "keywords": sorted(set(keyword_matches)),
                "compound_patterns": sorted(compound_matches),
                "suspicious_tld": has_suspicious_tld,
                "is_suspicious": total_count > 0 or has_suspicious_tld
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "details": {"keyword_count": 0}
        }