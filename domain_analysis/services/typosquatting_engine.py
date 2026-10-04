"""
Typosquatting Detection Engine (v5 - Production Grade)
────────────────────────────────────────────────────────
Detects domain name impersonation with a multi-stage normalization pipeline:

  1. Normalization Pipeline (hyphen strip + char dedup + latin tricks)
  2. Direct brand match after normalization
  3. Bloom Filter → Trie → Levenshtein similarity pipeline
  4. Brand containment check with impersonation vs legitimate distinction
  5. Fuzzy brand matching (Levenshtein distance)

Critical Design Decision:
  The bloom filter whitelist is NO LONGER trusted blindly.
  If normalization reveals a brand match, the domain is flagged
  regardless of bloom filter status (prevents bloom filter poisoning).
"""

import re
import logging
from typing import Dict, Any, List, Set, Optional
from rapidfuzz import fuzz
from rapidfuzz.distance.Levenshtein import distance as levenshtein_distance

from .bloom_filter import is_legit_domain
from .trie_index import get_candidates
from .dataset_loader import SAFETY_WHITELIST
from .domain_utils import extract_domain_info, extract_canonical_labels
from .constants import LATIN_TRICKS, SENSITIVE_BRANDS, SHARED_HOSTING_PROVIDERS

logger = logging.getLogger(__name__)

# Dynamic Brand Service integration with static fallback
try:
    from apps.domains.services.brand_service import BrandService
except Exception:
    BrandService = None


def _get_active_brands() -> Set[str]:
    """Retrieves active sensitive brands from dynamic catalog with static fallback."""
    if BrandService:
        try:
            return BrandService.get_sensitive_brands()
        except Exception:
            pass
    return SENSITIVE_BRANDS


def _get_token_boundary_keywords() -> Dict[str, Dict[str, Any]]:
    """Retrieves token boundary keywords from dynamic catalog with static fallback."""
    if BrandService:
        try:
            return BrandService.get_token_boundary_keywords()
        except Exception:
            pass
    # Fallback for short brands <= 3 chars
    fallback = {}
    for b in SENSITIVE_BRANDS:
        if len(b) <= 3:
            fallback[b] = {"brand_slug": b, "brand_name": b, "weight": 1.0}
    return fallback


# --- Configuration ---
SIMILARITY_THRESHOLD = 80
LEVENSHTEIN_MAX_DISTANCE = 3  # Max edit distance for brand fuzzy match


# Real domains for sensitive brands — used to distinguish
# legitimate brand domains from impersonation attempts.
# e.g., "facebook.com" is legit, "faccebook.com" is NOT.
BRAND_REAL_DOMAINS = {
    "instagram": {"instagram.com"},
    "facebook": {"facebook.com", "fb.com"},
    "whatsapp": {"whatsapp.com"},
    "twitter": {"twitter.com", "x.com"},
    "tiktok": {"tiktok.com"},
    "discord": {"discord.com", "discord.gg"},
    "telegram": {"telegram.org", "t.me"},
    "snapchat": {"snapchat.com"},
    "linkedin": {"linkedin.com"},
    "pinterest": {"pinterest.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com"},
    "amazon": {"amazon.com", "aws.amazon.com"},
    "netflix": {"netflix.com"},
    "outlook": {"outlook.com", "outlook.live.com"},
    "onedrive": {"onedrive.com", "onedrive.live.com"},
    "office365": {"office365.com", "office.com"},
    "office": {"office.com"},
    "paypal": {"paypal.com"},
    "stripe": {"stripe.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "blockchain": {"blockchain.com"},
    "trustwallet": {"trustwallet.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "capitalone": {"capitalone.com"},
    "hsbc": {"hsbc.com"},
    "citibank": {"citibank.com", "citi.com"},
    "barclays": {"barclays.com"},
    "oracle": {"oracle.com"},
    "ibm": {"ibm.com"},
    "cisco": {"cisco.com"},
    "intel": {"intel.com"},
    "nvidia": {"nvidia.com"},
    "icloud": {"icloud.com"},
    "dropbox": {"dropbox.com"},
    "salesforce": {"salesforce.com"},
    "adobe": {"adobe.com"},
    "zoom": {"zoom.us"},
    "slack": {"slack.com"},
    "shopify": {"shopify.com"},
    "wordpress": {"wordpress.com"},
    "steam": {"steampowered.com", "store.steampowered.com"},
    "steamcommunity": {"steamcommunity.com"},
    "roblox": {"roblox.com"},
    "epicgames": {"epicgames.com"},
    "epic": {"epicgames.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "dhl": {"dhl.com"},
    "openai": {"openai.com"},
    "chatgpt": {"chatgpt.com", "chat.openai.com"},
    # MENA Banking & Fintech
    "alrajhibank": {"alrajhibank.com.sa", "alrajhi.bank"},
    "alrajhi": {"alrajhibank.com.sa", "alrajhi.bank"},
    "alahli": {"alahli.com", "alahlionline.com"},
    "snb": {"alahli.com", "snb.com.sa"},
    "riyadbank": {"riyadbank.com"},
    "alinma": {"alinma.com"},
    "albilad": {"bankalbilad.com"},
    "anb": {"anb.com.sa"},
    "stcpay": {"stcpay.com.sa"},
    "urpay": {"urpay.com.sa"},
    "cib": {"cibeg.com"},
    "banquemisr": {"banquemisr.com"},
    "nbe": {"nbe.com.eg"},
    "instapay": {"instapay.eg"},
    "vodafonecash": {"vodafone.com.eg"},
    "qnb": {"qnb.com"},
    "adcb": {"adcb.com"},
    "bankfab": {"bankfab.com"},
    # MENA Government & Essential Platforms
    "absher": {"absher.sa"},
    "nafath": {"nafath.sa", "iam.gov.sa"},
    "tawakkalna": {"tawakkalna.sdaia.gov.sa", "tawakkalna.sa"},
    "qiwa": {"qiwa.sa"},
    "muqeem": {"muqeem.sa"},
    "gosi": {"gosi.gov.sa"},
    "zatca": {"zatca.gov.sa"},
    "balady": {"balady.gov.sa"},
    "etimad": {"etimad.sa"},
    "sehhaty": {"sehhaty.sa"},
    # MENA Telecom
    "stc": {"stc.com.sa", "stc.com"},
    "mobily": {"mobily.com.sa"},
    "zain": {"zain.com", "sa.zain.com"},
    "vodafone": {"vodafone.com", "vodafone.com.eg"},
    "etisalat": {"etisalat.ae", "etisalat.eg", "eand.com"},
    "orange": {"orange.com", "orange.eg"},
    # MENA E-Commerce & Delivery
    "noon": {"noon.com"},
    "jarir": {"jarir.com"},
    "hungerstation": {"hungerstation.com"},
    "jahez": {"jahez.net"},
    "talabat": {"talabat.com"},
    "mrsool": {"mrsool.co"},
}


# ── Normalization Pipeline ────────────────────────────────────────────────

def _normalize_domain(domain: str) -> str:
    """
    Full normalization pipeline for typosquatting detection.
    
    Pipeline:
      1. Extract main part (before TLD)
      2. Strip all hyphens (fa-ce-book → facebook)
      3. Collapse repeated adjacent characters (faccebook → facebook)
      4. Apply Latin trick substitutions (rn → m, 0 → o, etc.)
    
    Returns the fully normalized main part (no TLD).
    """
    main_part = domain.split(".")[0].lower()
    
    # Step 1: Strip hyphens
    normalized = main_part.replace("-", "")
    
    # Step 2: Collapse repeated adjacent characters
    # "faccebook" → "facebook", "faacceebook" → "facebook"
    normalized = re.sub(r'(.)\1+', r'\1', normalized)
    
    # Step 3: Apply Latin trick substitutions
    for trick, real_char in LATIN_TRICKS.items():
        normalized = normalized.replace(trick, real_char)
    
    return normalized


def _is_real_brand_domain(domain: str, brand: str) -> bool:
    """
    Checks if the domain IS the real/official domain for a brand.
    Uses dynamic BrandService with fallback to BRAND_REAL_DOMAINS.
    """
    if not domain or not brand:
        return False
    if BrandService:
        try:
            return BrandService.is_official_domain_for_brand(domain, brand)
        except Exception:
            pass
    real_domains = BRAND_REAL_DOMAINS.get(brand.lower(), set())
    return domain.lower() in real_domains


def _detect_subdomain_impersonation(host: str) -> Optional[Dict[str, Any]]:
    """
    Detects if a sensitive brand is hidden in the subdomain.
    e.g. paypal-login-secure.example.com or snb.secure-login.com
    """
    canonical = extract_canonical_labels(host)
    subdomain = canonical.get("subdomain", "").lower()
    root_domain = canonical.get("registrable_domain", "").lower()
    tokens = canonical.get("tokens", set())
    
    if not subdomain:
        return None

    # Check token-boundary keywords in subdomain (e.g. snb, cib, stc)
    token_boundary_kws = _get_token_boundary_keywords()
    for kw, meta in token_boundary_kws.items():
        if kw in tokens and not _is_real_brand_domain(root_domain, kw):
            return {
                "is_typosquatting": True,
                "brand_impersonation": True,
                "target_brand": kw,
                "brand_name": meta.get("brand_name", kw),
                "method": "subdomain_token_impersonation",
                "confidence": 0.96,
                "reason": f"Brand token '{kw}' found in subdomain of unverified root domain"
            }

    active_brands = _get_active_brands()
    for brand in active_brands:
        if len(brand) < 4 and brand not in token_boundary_kws:
            continue
        
        if brand in subdomain:
            # If the brand is in the subdomain, ensure the root is NOT the real brand
            if brand not in root_domain and not _is_real_brand_domain(root_domain, brand):
                return {
                    "is_typosquatting": True,
                    "brand_impersonation": True,
                    "target_brand": brand,
                    "method": "subdomain_impersonation",
                    "confidence": 0.95,
                    "reason": f"Brand '{brand}' found in subdomain but not in root domain"
                }
    return None



def _normalize_latin_tricks(domain: str) -> str:
    """Normalize a domain by replacing Latin manipulation tricks only."""
    normalized = domain.lower()
    for trick, real_char in LATIN_TRICKS.items():
        normalized = normalized.replace(trick, real_char)
    return normalized


def _is_same_root(domain1: str, domain2: str) -> bool:
    """Check if two domains share the same root (last 2 parts)."""
    parts1 = domain1.lower().split(".")
    parts2 = domain2.lower().split(".")
    root1 = ".".join(parts1[-2:]) if len(parts1) >= 2 else domain1.lower()
    root2 = ".".join(parts2[-2:]) if len(parts2) >= 2 else domain2.lower()
    return root1 == root2


def _generate_candidates(domain: str) -> List[str]:
    """Generates potential 'legit' candidates via trie index based on the root domain."""
    if not domain: return []
    
    # Extract registrable domain's main part
    info = extract_domain_info(domain)
    root = info.get("registrable_domain", "").lower()
    if not root: root = domain.lower()
    
    main_part = root.split(".")[0]
    
    candidates: Set[str] = set()
    if len(main_part) >= 3:
        candidates.update(get_candidates(main_part[:3]))
        candidates.update(get_candidates(main_part[-3:]))
    if len(main_part) > 5:
        candidates.update(get_candidates(main_part[:5]))

    # Filter by similar length
    return [c for c in candidates if abs(len(c.split(".")[0]) - len(main_part)) <= 2]


def _compute_similarity(domain: str, candidates: List[str]) -> Optional[Dict[str, Any]]:
    """Computes similarity and returns best match if above threshold, comparing root domains."""
    if not domain or not candidates: return None
    
    info = extract_domain_info(domain)
    root = info.get("registrable_domain", "").lower()
    if not root: root = domain.lower()
    domain_main = root.split(".")[0]

    best_match = None
    max_score = 0

    for legit in candidates:
        if _is_same_root(legit, domain): continue
        legit_main = legit.split(".")[0]

        # Short acronyms/brands (< 4 chars e.g. snb, cib, stc) must match via Token-Boundary, not fuzzy distance
        if len(legit_main) < 4 and domain_main != legit_main:
            continue
        
        # ── TLD-Squatting / Exact Match Logic ──────────────────────────────
        # If names match exactly (nulls.gg vs nulls.de), only flag if the 
        # target is a sensitive brand. Random domains sharing a name are not 
        # necessarily typosquatting.
        if domain_main == legit_main:
            is_brand = False
            for brand in SENSITIVE_BRANDS:
                if domain_main == _normalize_domain(brand):
                    is_brand = True
                    break
            
            if not is_brand:
                # Same name but not a brand -> likely unrelated legitimate domains
                continue

        score = fuzz.ratio(domain_main, legit_main)
        partial = fuzz.partial_ratio(domain_main, legit_main)
        confidence = (score * 0.7) + (partial * 0.3)
        
        if confidence > max_score:
            max_score = confidence
            best_match = legit

    if max_score >= SIMILARITY_THRESHOLD:
        # Final confidence adjustment: Non-brand matches are less certain
        is_brand_match = False
        target_main = best_match.split(".")[0]
        for brand in SENSITIVE_BRANDS:
            if target_main == _normalize_domain(brand):
                is_brand_match = True
                break
                
        final_confidence = max_score
        if not is_brand_match:
            final_confidence *= 0.8  # Reduce confidence for generic matches
            if final_confidence < 75: return None

        return {
            "match": best_match,
            "confidence": round(final_confidence, 2),
            "method": "levenshtein_combined",
            "is_brand": is_brand_match
        }
    return None


# ── Main Entry Point ──────────────────────────────────────────────────────

def detect_typosquatting(domain: str) -> Dict[str, Any]:
    """
    Detects if the domain is a typosquatting attempt of a legitimate domain.
    
    Uses a multi-stage pipeline with normalization-first approach to defeat
    bloom filter poisoning and character repetition attacks.
    """
    if not domain:
        return {"status": "error", "error": "No domain provided", "details": {"is_typosquatting": False}}

    try:
        # Step 0: Subdomain Impersonation Check (NEW)
        # This catches brands hidden in subdomains (e.g. paypal.secure-login.com)
        subdomain_impersonation = _detect_subdomain_impersonation(domain)
        if subdomain_impersonation:
            logger.warning(f"[TYPOSQUATTING] Subdomain impersonation detected: {domain}")
            return {"status": "ok", "details": subdomain_impersonation}

        # Step 0.5: Extract Registrable Domain (Root Domain) & Canonical Labels
        canonical = extract_canonical_labels(domain)
        root_domain = canonical.get("registrable_domain", "").lower()
        if not root_domain:
            root_domain = domain.lower()
        main_part = canonical.get("main_part", "").lower()
        if not main_part:
            main_part = root_domain.split(".")[0]
        tokens = canonical.get("tokens", set())
            
        # ── Shared Hosting Platform Guard ─────────────────────────────────
        # If the root domain IS a shared hosting provider (vercel.app, github.io),
        # we skip typosquatting checks on the root itself. 
        # (Subdomain impersonation was already checked in Step 0).
        if root_domain in SHARED_HOSTING_PROVIDERS:
            return {"status": "ok", "details": {"is_typosquatting": False, "reason": "Shared hosting platform root"}}

        active_brands = _get_active_brands()

        # Step 1: Strict Safe Whitelist & Verified Official Brand Domains
        if _is_real_brand_domain(domain, main_part) or _is_real_brand_domain(root_domain, main_part):
            return {"status": "ok", "details": {"is_typosquatting": False, "reason": "Verified official brand domain"}}

        if root_domain in SAFETY_WHITELIST or domain in SAFETY_WHITELIST:
            return {"status": "ok", "details": {"is_typosquatting": False, "reason": "Legitimate domain"}}

        # ── Step 1.5: Token-Boundary Brand Detection (for short/abbreviated brands) ──
        # Handles 3-letter & delimited brands (e.g. snb, cib, anb, stc, dhl) without False Positives
        token_boundary_kws = _get_token_boundary_keywords()
        for kw, meta in token_boundary_kws.items():
            if kw in tokens:
                # Is this the actual official domain for this brand?
                if _is_real_brand_domain(domain, kw) or _is_real_brand_domain(root_domain, kw):
                    return {"status": "ok", "details": {
                        "is_typosquatting": False,
                        "reason": f"Verified official {kw} domain"
                    }}
                else:
                    logger.warning(f"[TYPOSQUATTING] Token-boundary brand impersonation detected: {domain} (brand: {kw})")
                    return {"status": "ok", "details": {
                        "is_typosquatting": True,
                        "brand_impersonation": True,
                        "target_brand": kw,
                        "brand_name": meta.get("brand_name", kw),
                        "original_domain": domain,
                        "method": "token_boundary_match",
                        "confidence": 0.96
                    }}

        # ── Step 2: Normalization Pipeline (NEW - v5) ─────────────────────
        # This runs BEFORE the bloom filter to defeat bloom filter poisoning.
        # If normalization reveals a brand match, flag immediately.
        normalized_full = _normalize_domain(root_domain)
        
        for brand in active_brands:
            if normalized_full == _normalize_domain(brand):
                # Normalized domain matches a brand exactly!
                # But is this the REAL brand domain?
                if _is_real_brand_domain(domain, brand):
                    # It's the actual brand domain → safe
                    return {"status": "ok", "details": {
                        "is_typosquatting": False,
                        "reason": f"Verified real {brand} domain"
                    }}
                else:
                    # Impersonation! Domain normalizes to brand but ISN'T the real domain
                    logger.warning(f"[TYPOSQUATTING] Character manipulation detected: {domain} → {normalized_full} (brand: {brand})")
                    return {"status": "ok", "details": {
                        "is_typosquatting": True,
                        "brand_impersonation": True,
                        "target_brand": brand,
                        "normalized_form": normalized_full,
                        "original_domain": domain,
                        "method": "normalization_pipeline",
                        "confidence": 0.97
                    }}

        # ── Step 2.5: Latin Character Manipulation Detection ──────────────
        normalized_latin = _normalize_latin_tricks(main_part)
        if normalized_latin != main_part:
            for tld in [".com", ".org", ".net", ".io"]:
                if is_legit_domain(normalized_latin + tld):
                    return {
                        "status": "ok",
                        "details": {
                            "is_typosquatting": True,
                            "latin_manipulation": True,
                            "target_domain": normalized_latin + tld,
                            "confidence": 0.95
                        }
                    }

        # ── Step 3: Global Legit List (Bloom) ─────────────────────────────
        # IMPORTANT: Only trust bloom filter if normalization didn't find
        # anything suspicious. At this point, Step 2 already cleared
        # any brand impersonation via character manipulation.
        if is_legit_domain(domain):
            # Double-check: even if in bloom filter, verify no brand proximity
            # This catches edge cases where normalization doesn't exact-match
            # but the domain is still suspiciously close to a brand
            for brand in active_brands:
                if len(brand) >= 4:  # Only check meaningful brands
                    lev_dist = levenshtein_distance(main_part, brand)
                    if lev_dist <= 2 and main_part != brand:
                        # In bloom filter BUT very close to a brand → suspicious
                        if not _is_real_brand_domain(domain, brand):
                            logger.warning(f"[TYPOSQUATTING] Bloom filter override: {domain} is {lev_dist} edits from {brand}")
                            return {"status": "ok", "details": {
                                "is_typosquatting": True,
                                "brand_impersonation": True,
                                "target_brand": brand,
                                "edit_distance": lev_dist,
                                "method": "bloom_override_levenshtein",
                                "confidence": 0.90
                            }}
            
            return {"status": "ok", "details": {"is_typosquatting": False, "reason": "Legitimate whitelist match"}}

        # ── Step 4: Trie-based Similarity Search ──────────────────────────
        candidates = _generate_candidates(domain)
        if candidates:
            similarity = _compute_similarity(domain, candidates)
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

        # ── Step 4.5: Levenshtein Distance Brand Match ────────────────────
        # Uses dynamic thresholds based on brand length to prevent FPs.
        for brand in active_brands:
            brand_len = len(brand)
            if brand_len < 4: continue
            
            # Dynamic Thresholds:
            # - Short brands (4-5 chars): max 1 edit
            # - Medium brands (6-9 chars): max 2 edits
            # - Long brands (10+ chars): max 3 edits
            current_max_dist = 1 if brand_len <= 5 else (2 if brand_len <= 9 else 3)
            
            lev_dist = levenshtein_distance(main_part, brand)
            
            if lev_dist <= current_max_dist and main_part != brand:
                if not _is_real_brand_domain(domain, brand):
                    confidence = max(0.70, 1.0 - (lev_dist * 0.1))
                    # Normalized distance: 0.0 (identical) → 1.0 (max edits)
                    norm_dist = round(lev_dist / max(len(brand), 1), 4)
                    return {
                        "status": "ok",
                        "details": {
                            "is_typosquatting": True,
                            "brand_impersonation": True,
                            "target_brand": brand,
                            "edit_distance": lev_dist,
                            "normalized_distance": norm_dist,
                            "method": "levenshtein_brand_match",
                            "confidence": round(confidence, 2)
                        }
                    }

        # ── Step 5: Brand containment check ───────────────────────────────
        # e.g., "instagram-copyright.com" → contains "instagram"
        # But must distinguish from legitimate usage like "facebookmail.com"
        for brand in active_brands:
            if len(brand) < 4:
                continue
                
            if (brand in main_part or brand in normalized_full) and brand != main_part and brand != normalized_full:
                if not _is_real_brand_domain(domain, brand):
                    return {
                        "status": "ok",
                        "details": {
                            "is_typosquatting": True,
                            "brand_impersonation": True,
                            "target_brand": brand,
                            "confidence": 0.90
                        }
                    }

        return {"status": "ok", "details": {"is_typosquatting": False}}


    except Exception as e:
        logger.error(f"Typosquatting detection error: {e}", exc_info=True)
        return {"status": "error", "error": str(e), "details": {"is_typosquatting": False}}