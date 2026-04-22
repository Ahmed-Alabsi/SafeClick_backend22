"""
Feature Extractor v2 for XGBoost ML Engine
────────────────────────────────────────────
Extracts 45 numerical features from a raw URL for binary classification.
Designed for Zero-day Phishing Detection in SafeClick Hybrid Architecture.

Feature Groups:
    1. Lexical Features (URL string analysis) — 10 features
    2. Domain-Level Features (TLD, subdomain depth) — 10 features
    3. Statistical Features (Entropy, char distribution) — 9 features
    4. Suspicious Keyword Features (phishing vocabulary) — 8 features
    5. Zero-day Detection Features (NEW) — 8 features
"""

import math
import re
import string
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List
from collections import Counter

import logging

logger = logging.getLogger(__name__)

# ── Suspicious Keyword Vocabulary ──────────────────────────────────────
# Curated from real-world phishing campaigns (APWG, PhishTank, OpenPhish)
_PHISHING_KEYWORDS = frozenset([
    "login", "signin", "sign-in", "verify", "account", "update", "secure",
    "banking", "confirm", "password", "credential", "authenticate",
    "wallet", "suspend", "alert", "unlock", "restore", "recover",
    "billing", "payment", "invoice", "free", "gift", "reward", "prize",
    "urgent", "immediately", "expire", "limited", "offer",
])

_BRAND_KEYWORDS = frozenset([
    "paypal", "apple", "google", "microsoft", "facebook", "instagram",
    "amazon", "netflix", "chase", "wellsfargo", "coinbase", "metamask",
    "binance", "whatsapp", "telegram", "linkedin", "twitter", "dropbox",
    "icloud", "outlook", "yahoo", "steam", "ebay",
])

# ── Suspicious TLDs (commonly abused in phishing) ─────────────────────
_SUSPICIOUS_TLDS = frozenset([
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Freenom (free TLDs)
    ".top", ".xyz", ".club", ".info", ".online", ".site", ".work",
    ".click", ".link", ".buzz", ".surf", ".icu", ".shop", ".store",
    ".bid", ".win", ".loan", ".racing", ".review", ".stream",
])

# ── Free Registration TLDs (Zero-day favorite) ────────────────────────
_FREE_TLDS = frozenset([".tk", ".ml", ".ga", ".cf", ".gq", ".free"])

# ── Free Hosting Providers (commonly abused) ──────────────────────────
_FREE_HOSTING = frozenset([
    "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com",
    "wordpress.com", "godaddysites.com", "square.site", "carrd.co",
    "glitch.me", "netlify.app", "vercel.app", "herokuapp.com",
    "firebaseapp.com", "web.app", "pages.dev", "github.io",
    "sites.google.com", "duckdns.org", "no-ip.org", "ddns.net",
])

# ── Homoglyph Map (lookalike characters) ──────────────────────────────
_HOMOGLYPH_PAIRS = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
    "rn": "m", "vv": "w", "cl": "d", "nn": "m",
}

# ── Suspicious Path Extensions ────────────────────────────────────────
_SUSPICIOUS_EXTENSIONS = frozenset([
    ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl",
    ".exe", ".scr", ".bat", ".cmd", ".msi", ".dll",
])


def _shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string. Higher entropy = more randomness."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def _vowel_consonant_ratio(text: str) -> float:
    """Ratio of vowels to consonants. Gibberish domains have abnormal ratios."""
    vowels = sum(1 for c in text.lower() if c in "aeiou")
    consonants = sum(1 for c in text.lower() if c in "bcdfghjklmnpqrstvwxyz")
    if consonants == 0:
        return 0.0
    return round(vowels / consonants, 4)


def _digit_ratio(text: str) -> float:
    """Proportion of digits in text. Phishing URLs often embed excessive numbers."""
    if not text:
        return 0.0
    digits = sum(1 for c in text if c.isdigit())
    return round(digits / len(text), 4)


def _special_char_ratio(text: str) -> float:
    """Proportion of non-alphanumeric characters (excluding dots and slashes)."""
    if not text:
        return 0.0
    specials = sum(1 for c in text if c not in string.ascii_letters + string.digits + "./-_:")
    return round(specials / len(text), 4)


def _longest_consonant_sequence(text: str) -> int:
    """Longest sequence of consecutive consonants. Gibberish has long sequences."""
    consonants = "bcdfghjklmnpqrstvwxyz"
    max_seq = 0
    current = 0
    for c in text.lower():
        if c in consonants:
            current += 1
            max_seq = max(max_seq, current)
        else:
            current = 0
    return max_seq


def _has_homoglyph(domain: str) -> float:
    """Checks if domain contains homoglyph character substitutions."""
    domain_lower = domain.lower()
    
    # Check multi-char homoglyphs first (rn->m, vv->w, etc.)
    for fake, real in _HOMOGLYPH_PAIRS.items():
        if len(fake) > 1 and fake in domain_lower:
            # Check if replacing the homoglyph creates a known brand
            corrected = domain_lower.replace(fake, real)
            for brand in _BRAND_KEYWORDS:
                if brand in corrected and brand not in domain_lower:
                    return 1.0
    
    # Check single-char homoglyphs (0->o, 1->l, etc.)
    for fake, real in _HOMOGLYPH_PAIRS.items():
        if len(fake) == 1 and fake in domain_lower:
            corrected = domain_lower.replace(fake, real)
            for brand in _BRAND_KEYWORDS:
                if brand in corrected and brand not in domain_lower:
                    return 1.0
    
    return 0.0


def _brand_similarity_score(domain: str) -> float:
    """
    Checks how similar the domain is to a known brand.
    Returns the best similarity score (0.0 to 1.0).
    Uses character-level comparison (cheaper than Levenshtein).
    """
    domain_lower = domain.lower().split(".")[0]  # Get just the main domain part
    
    if len(domain_lower) < 3:
        return 0.0
    
    best_score = 0.0
    for brand in _BRAND_KEYWORDS:
        # Quick length check
        if abs(len(domain_lower) - len(brand)) > 3:
            continue
        
        # Character overlap score
        brand_set = set(brand)
        domain_set = set(domain_lower)
        overlap = len(brand_set & domain_set)
        total = len(brand_set | domain_set)
        if total > 0:
            jaccard = overlap / total
            if jaccard > best_score:
                best_score = jaccard
    
    return round(best_score, 4)


def _is_free_hosting(host: str) -> float:
    """Checks if the URL is hosted on a free platform commonly abused."""
    host_lower = host.lower()
    for provider in _FREE_HOSTING:
        if host_lower.endswith(provider) or host_lower.endswith("." + provider):
            return 1.0
    return 0.0


def extract_features(url: str) -> Dict[str, float]:
    """
    Extracts a fixed-size feature vector (45 features) from a URL.
    Returns a dictionary of feature_name -> float value, ready for XGBoost input.
    
    This function is designed to be:
      - Deterministic (no network calls, no randomness)
      - Fast (< 0.1ms per URL on modern hardware)
      - Compatible with batch processing for training datasets
    """
    features = {}
    
    # Ensure scheme exists
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    try:
        parsed = urlparse(url)
    except Exception:
        # Return zero vector on catastrophic parse failure
        return _zero_features()
    
    host = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    
    # Remove port from host if present
    host_no_port = host.split(":")[0] if ":" in host else host
    
    # Extract domain parts
    domain_parts = host_no_port.split(".")
    
    # Core domain (e.g., "google" from "mail.google.com")
    domain_core = domain_parts[-2] if len(domain_parts) >= 2 else host_no_port
    
    # Subdomain string
    subdomain = ".".join(domain_parts[:-2]).lower() if len(domain_parts) > 2 else ""
    
    # TLD
    tld = "." + domain_parts[-1].lower() if domain_parts else ""
    
    # Full path with query
    full_path = path + ("?" + query if query else "")
    
    # ════════════════════════════════════════════════════════════════════
    # GROUP 1: Lexical Features (10 features)
    # ════════════════════════════════════════════════════════════════════
    features["url_length"] = len(url)
    features["host_length"] = len(host_no_port)
    features["path_length"] = len(path)
    features["query_length"] = len(query)
    features["fragment_length"] = len(fragment)
    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["at_symbol"] = 1.0 if "@" in url else 0.0
    features["double_slash_count"] = url.count("//") - 1  # Subtract the scheme's //
    features["has_https"] = 1.0 if parsed.scheme == "https" else 0.0
    
    # ════════════════════════════════════════════════════════════════════
    # GROUP 2: Domain-Level Features (10 features) — expanded
    # ════════════════════════════════════════════════════════════════════
    features["subdomain_count"] = max(0, len(domain_parts) - 2)
    features["domain_token_count"] = len(domain_parts)
    features["tld_length"] = len(domain_parts[-1]) if domain_parts else 0
    
    # Is the host a raw IP address?
    features["is_ip_address"] = 1.0 if _is_ip(host_no_port) else 0.0
    
    # Suspicious TLD check
    features["is_suspicious_tld"] = 1.0 if tld in _SUSPICIOUS_TLDS else 0.0
    
    # Port present in URL (non-standard ports are suspicious)
    features["has_port"] = 1.0 if ":" in host and not host.startswith("[") else 0.0
    
    # Domain contains digits (e.g., g00gle.com, amaz0n.com)
    features["domain_digit_count"] = sum(1 for c in domain_core if c.isdigit())
    
    # NEW: Free TLD (tk, ml, ga, cf, gq)
    features["is_free_tld"] = 1.0 if tld in _FREE_TLDS else 0.0
    
    # NEW: Free hosting platform
    features["is_free_hosting"] = _is_free_hosting(host_no_port)
    
    # NEW: Domain registered name length (just the core, no TLD)
    features["domain_name_length"] = len(domain_core)
    
    # ════════════════════════════════════════════════════════════════════
    # GROUP 3: Statistical Features (9 features) — expanded
    # ════════════════════════════════════════════════════════════════════
    features["url_entropy"] = _shannon_entropy(url)
    features["domain_entropy"] = _shannon_entropy(host_no_port)
    features["path_entropy"] = _shannon_entropy(path)
    features["digit_ratio"] = _digit_ratio(url)
    features["special_char_ratio"] = _special_char_ratio(url)
    features["vowel_consonant_ratio"] = _vowel_consonant_ratio(domain_core)
    
    # Longest continuous token without separator (indicator of obfuscation)
    tokens = re.split(r"[.\-_/]", url)
    features["max_token_length"] = max((len(t) for t in tokens), default=0)
    
    # NEW: Domain-specific entropy (high = random/DGA domain)
    features["domain_core_entropy"] = _shannon_entropy(domain_core)
    
    # NEW: Longest consonant sequence (gibberish detection)
    features["consonant_sequence"] = _longest_consonant_sequence(domain_core)
    
    # ════════════════════════════════════════════════════════════════════
    # GROUP 4: Suspicious Keyword Features (8 features) — expanded
    # ════════════════════════════════════════════════════════════════════
    url_lower = url.lower()
    
    features["phishing_keyword_count"] = sum(1 for kw in _PHISHING_KEYWORDS if kw in url_lower)
    features["brand_keyword_count"] = sum(1 for kw in _BRAND_KEYWORDS if kw in url_lower)
    
    # Brand in subdomain (classic phishing: paypal.evil.com)
    features["brand_in_subdomain"] = 1.0 if any(b in subdomain for b in _BRAND_KEYWORDS) else 0.0
    
    # Brand in path (e.g., evil.com/paypal-login)
    features["brand_in_path"] = 1.0 if any(b in path.lower() for b in _BRAND_KEYWORDS) else 0.0
    
    # Encoded characters in URL (obfuscation technique)
    features["encoded_char_count"] = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    
    # Query parameter count (phishing URLs often have many params)
    try:
        features["query_param_count"] = len(parse_qs(query))
    except Exception:
        features["query_param_count"] = 0
    
    # NEW: Has redirect parameter (common phishing: url=, redirect=, next=)
    features["has_redirect_param"] = 1.0 if re.search(
        r"[?&](url|redirect|next|return|goto|link|target|dest|redir|continue)=",
        url_lower
    ) else 0.0
    
    # NEW: Phishing keywords in domain (not just in URL)
    features["phishing_keyword_in_domain"] = 1.0 if any(
        kw in host_no_port.lower() for kw in ["login", "signin", "verify", "secure", "update", "confirm", "password", "account"]
    ) else 0.0
    
    # ════════════════════════════════════════════════════════════════════
    # GROUP 5: Zero-day Detection Features (8 features) — NEW
    # ════════════════════════════════════════════════════════════════════
    
    # URL depth (number of path segments)
    path_segments = [s for s in path.split("/") if s]
    features["url_depth"] = len(path_segments)
    
    # Suspicious file extension in path
    features["suspicious_extension"] = 1.0 if any(
        path.lower().endswith(ext) for ext in _SUSPICIOUS_EXTENSIONS
    ) else 0.0
    
    # Homoglyph detection (lookalike characters targeting brands)
    features["has_homoglyph"] = _has_homoglyph(host_no_port)
    
    # Brand similarity score (how close is domain to a known brand)
    features["brand_similarity"] = _brand_similarity_score(domain_core)
    
    # Subdomain length (very long subdomains are suspicious)
    features["subdomain_length"] = len(subdomain)
    
    # Longest subdomain token
    subdomain_tokens = subdomain.split(".") if subdomain else []
    features["longest_subdomain_token"] = max(
        (len(t) for t in subdomain_tokens), default=0
    )
    
    # Domain-to-path length ratio (phishing: short domain, long path)
    features["domain_path_ratio"] = (
        len(host_no_port) / max(len(full_path), 1)
    )
    
    # Digit-to-letter ratio in domain (DGA detection)
    letters = sum(1 for c in domain_core if c.isalpha())
    digits = sum(1 for c in domain_core if c.isdigit())
    features["domain_digit_letter_ratio"] = (
        digits / max(letters, 1)
    )
    
    return features


def extract_features_vector(url: str) -> List[float]:
    """
    Returns features as an ordered list (vector) suitable for direct XGBoost input.
    The order is guaranteed to be consistent with FEATURE_NAMES.
    """
    feat_dict = extract_features(url)
    return [feat_dict.get(name, 0.0) for name in FEATURE_NAMES]


def _is_ip(host: str) -> bool:
    """Check if host is a raw IPv4 or IPv6 address."""
    # IPv4
    parts = host.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            pass
    # T11 FIX: IPv6 uses bracket notation in URLs: [::1], [2001:db8::1]
    # The old check `":" in host` was a false positive for port numbers (evil.com:8080).
    if host.startswith("[") and "]" in host:
        return True
    return False


def _zero_features() -> Dict[str, float]:
    """Returns a zero-valued feature dictionary for error cases."""
    return {name: 0.0 for name in FEATURE_NAMES}


# ── Canonical Feature Order (MUST match training) ─────────────────────
# This list defines the exact column order for the XGBoost model.
# DO NOT reorder or remove items without retraining the model.
FEATURE_NAMES = [
    # Group 1: Lexical (10)
    "url_length", "host_length", "path_length", "query_length",
    "fragment_length", "dot_count", "hyphen_count", "at_symbol",
    "double_slash_count", "has_https",
    # Group 2: Domain (10)
    "subdomain_count", "domain_token_count", "tld_length",
    "is_ip_address", "is_suspicious_tld", "has_port", "domain_digit_count",
    "is_free_tld", "is_free_hosting", "domain_name_length",
    # Group 3: Statistical (9)
    "url_entropy", "domain_entropy", "path_entropy",
    "digit_ratio", "special_char_ratio", "vowel_consonant_ratio",
    "max_token_length", "domain_core_entropy", "consonant_sequence",
    # Group 4: Keywords (8)
    "phishing_keyword_count", "brand_keyword_count",
    "brand_in_subdomain", "brand_in_path",
    "encoded_char_count", "query_param_count",
    "has_redirect_param", "phishing_keyword_in_domain",
    # Group 5: Zero-day Detection (8)
    "url_depth", "suspicious_extension", "has_homoglyph",
    "brand_similarity", "subdomain_length", "longest_subdomain_token",
    "domain_path_ratio", "domain_digit_letter_ratio",
]
