# apps/domains/services/brand_service.py
"""
Brand Intelligence Service
──────────────────────────
High-performance dynamic catalog service for sensitive brands, official domains,
and impersonation detection patterns.

Architecture:
  - Multi-tier cache: In-Process memory cache ($O(1)$, ~0ms) checked against Redis version key.
  - Light transaction invalidation: bumping version key in Redis via transaction.on_commit().
  - Observable fallback: Automatic fallback to static baseline with engine health logging if DB fails.
"""

import threading
import logging
from datetime import datetime
from typing import Dict, Set, List, Optional, Any
from django.core.cache import cache

logger = logging.getLogger(__name__)

CATALOG_VERSION_KEY = "safeclick:catalog:version"


class BrandService:
    _lock = threading.Lock()
    _cached_catalog: Optional[Dict[str, Any]] = None
    _cached_version: int = 0

    @classmethod
    def bump_version(cls) -> int:
        """
        Lightweight atomic operation to bump catalog version in Redis.
        Workers lazily reload their in-process catalog on the next request.
        """
        try:
            new_v = cache.incr(CATALOG_VERSION_KEY)
        except ValueError:
            # Key does not exist in cache yet
            cache.set(CATALOG_VERSION_KEY, 1, timeout=None)
            new_v = 1
        except Exception as e:
            logger.warning(f"[BRAND_SERVICE] Redis error bumping catalog version: {e}")
            new_v = cls._cached_version + 1

        cls._cached_version = 0  # Invalidate local worker cache
        logger.info(f"[BRAND_SERVICE] Catalog version bumped to v{new_v}")
        return new_v

    @classmethod
    def get_current_version(cls) -> int:
        """Returns the current catalog version from Redis."""
        try:
            v = cache.get(CATALOG_VERSION_KEY)
            if v is None:
                cache.set(CATALOG_VERSION_KEY, 1, timeout=None)
                return 1
            return int(v)
        except Exception:
            return 1

    @classmethod
    def get_catalog(cls) -> Dict[str, Any]:
        """
        Returns the active catalog dictionary from memory.
        Lazily reloads from DB if Redis version has changed.
        """
        current_v = cls.get_current_version()
        if cls._cached_catalog is not None and cls._cached_version == current_v:
            return cls._cached_catalog

        with cls._lock:
            # Double-check inside lock
            if cls._cached_catalog is not None and cls._cached_version == current_v:
                return cls._cached_catalog

            catalog = cls._load_from_db(current_v)
            cls._cached_catalog = catalog
            cls._cached_version = current_v
            return cls._cached_catalog

    @classmethod
    def clear_cache(cls):
        """Resets the in-process catalog cache (useful for tests and resets)."""
        with cls._lock:
            cls._cached_catalog = None
            cls._cached_version = 0

    @classmethod
    def _load_from_db(cls, version: int) -> Dict[str, Any]:
        """
        Loads catalog from database models. If called from an active asyncio
        event loop context, offloads the ORM queries to a worker thread
        to prevent Django's SynchronousOnlyOperation.
        """
        import asyncio
        import concurrent.futures

        try:
            asyncio.get_running_loop()
            in_async = True
        except RuntimeError:
            in_async = False

        if in_async:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(cls._load_from_db_sync, version).result()
        return cls._load_from_db_sync(version)

    @classmethod
    def _load_from_db_sync(cls, version: int) -> Dict[str, Any]:
        """
        Synchronously loads catalog from database models, overlaying dynamic updates
        on top of the verified baseline intelligence catalog.
        """
        # Always initialize with the verified baseline catalog foundation
        base_catalog = cls._get_static_fallback(reason="BASELINE")
        official_domains: Set[str] = set(base_catalog["official_domains"])
        brand_real_domains: Dict[str, Set[str]] = {k: set(v) for k, v in base_catalog["brand_real_domains"].items()}
        sensitive_brands: Set[str] = set(base_catalog["sensitive_brands"])
        token_boundary_keywords: Dict[str, Dict[str, Any]] = dict(base_catalog["token_boundary_keywords"])
        typo_similarity_keywords: Dict[str, Dict[str, Any]] = dict(base_catalog["typo_similarity_keywords"])
        contains_keywords: Dict[str, Dict[str, Any]] = dict(base_catalog.get("contains_keywords", {}))
        exact_keywords: Dict[str, Dict[str, Any]] = dict(base_catalog.get("exact_keywords", {}))

        try:
            from apps.domains.models import Brand, BrandDomain, BrandKeyword

            brands = Brand.objects.filter(is_active=True).prefetch_related('domains', 'keywords')

            for brand in brands:
                slug = brand.slug.lower()
                sensitive_brands.add(slug)

                # Verified official domains only
                verified_domains = {
                    d.domain.lower() for d in brand.domains.all()
                    if d.is_active and d.status == 'VERIFIED'
                }
                official_domains.update(verified_domains)
                if slug in brand_real_domains:
                    brand_real_domains[slug].update(verified_domains)
                else:
                    brand_real_domains[slug] = verified_domains

                for kw_obj in brand.keywords.all():
                    if not kw_obj.is_active:
                        continue
                    kw = kw_obj.keyword.lower()
                    sensitive_brands.add(kw)
                    # Also link keyword to real domains
                    if kw in brand_real_domains:
                        brand_real_domains[kw].update(verified_domains)
                    else:
                        brand_real_domains[kw] = verified_domains

                    kw_meta = {
                        "brand_slug": slug,
                        "brand_name": brand.name,
                        "brand_name_ar": brand.name_ar,
                        "sector": brand.sector,
                        "risk_weight": brand.risk_weight,
                        "weight": kw_obj.weight,
                        "match_strategy": kw_obj.match_strategy,
                    }

                    strat = kw_obj.match_strategy
                    if strat == 'TOKEN_BOUNDARY':
                        token_boundary_keywords[kw] = kw_meta
                    elif strat == 'TYPO_SIMILARITY':
                        typo_similarity_keywords[kw] = kw_meta
                    elif strat == 'CONTAINS':
                        contains_keywords[kw] = kw_meta
                    elif strat == 'EXACT':
                        exact_keywords[kw] = kw_meta
                    else:
                        token_boundary_keywords[kw] = kw_meta

            logger.info(
                f"[BRAND_SERVICE] Loaded DB Catalog v{version}: "
                f"{len(brands)} brands, {len(official_domains)} verified domains, "
                f"{len(sensitive_brands)} keywords."
            )

            return {
                "version": version,
                "loaded_at": datetime.now().isoformat(),
                "source": "DATABASE",
                "official_domains": official_domains,
                "brand_real_domains": brand_real_domains,
                "sensitive_brands": sensitive_brands,
                "token_boundary_keywords": token_boundary_keywords,
                "typo_similarity_keywords": typo_similarity_keywords,
                "contains_keywords": contains_keywords,
                "exact_keywords": exact_keywords,
            }

        except Exception as e:
            # If in SimpleTestCase (DB forbidden) or settings not ready, log concise warning
            err_str = str(e)
            if "DatabaseOperationForbidden" in type(e).__name__ or "ImproperlyConfigured" in type(e).__name__:
                logger.info(f"[BRAND_SERVICE] Database not accessible ({type(e).__name__}). Using fallback catalog.")
            else:
                logger.warning(f"[BRAND_SERVICE] Database catalog load failed ({e}). Using fallback catalog.")
            return cls._get_static_fallback(reason=err_str)


    @classmethod
    def _get_static_fallback(cls, reason: str = "") -> Dict[str, Any]:
        """Provides static fallback catalog when database is not available."""
        from domain_analysis.services.constants import SENSITIVE_BRANDS as STATIC_BRANDS
        from domain_analysis.services.typosquatting_engine import BRAND_REAL_DOMAINS as STATIC_REAL_DOMAINS
        from domain_analysis.services.dataset_loader import SAFETY_WHITELIST as STATIC_WHITELIST

        official_domains = set(STATIC_WHITELIST)
        brand_real_domains = dict(STATIC_REAL_DOMAINS)
        sensitive_brands = set(STATIC_BRANDS)

        token_boundary = {}
        typo_similarity = {}

        # Default heuristic classification for static fallback
        for brand in sensitive_brands:
            meta = {
                "brand_slug": brand,
                "brand_name": brand.title(),
                "brand_name_ar": "",
                "sector": "banking" if any(b in brand for b in ["bank", "rajhi", "ahli", "snb", "cib", "pay"]) else "other",
                "risk_weight": "HIGH",
                "weight": 1.0,
                "match_strategy": "TOKEN_BOUNDARY" if len(brand) <= 3 else "TYPO_SIMILARITY"
            }
            if len(brand) <= 3:
                token_boundary[brand] = meta
            else:
                typo_similarity[brand] = meta

        return {
            "version": 0,
            "loaded_at": datetime.now().isoformat(),
            "source": "FALLBACK_STATIC",
            "fallback_reason": reason,
            "official_domains": official_domains,
            "brand_real_domains": brand_real_domains,
            "sensitive_brands": sensitive_brands,
            "token_boundary_keywords": token_boundary,
            "typo_similarity_keywords": typo_similarity,
            "contains_keywords": {},
            "exact_keywords": {},
        }

    # ── High-Speed Query Helpers ──────────────────────────────────────────

    @classmethod
    def is_verified_official_domain(cls, domain: str) -> bool:
        """Checks if domain is in the verified official brand domains whitelist."""
        if not domain:
            return False
        cat = cls.get_catalog()
        return domain.lower() in cat["official_domains"]

    @classmethod
    def is_official_domain_for_brand(cls, domain: str, brand: str) -> bool:
        """Checks if domain is the legitimate domain for the specific brand."""
        if not domain or not brand:
            return False
        cat = cls.get_catalog()
        real_domains = cat["brand_real_domains"].get(brand.lower(), set())
        return domain.lower() in real_domains

    @classmethod
    def get_sensitive_brands(cls) -> Set[str]:
        """Returns the set of all sensitive brand keywords."""
        return cls.get_catalog()["sensitive_brands"]

    @classmethod
    def get_token_boundary_keywords(cls) -> Dict[str, Dict[str, Any]]:
        """Returns metadata map for short/delimited token boundary keywords."""
        return cls.get_catalog()["token_boundary_keywords"]

    @classmethod
    def get_typo_keywords(cls) -> Dict[str, Dict[str, Any]]:
        """Returns metadata map for Levenshtein typo similarity keywords."""
        return cls.get_catalog()["typo_similarity_keywords"]

    @classmethod
    def get_catalog_metadata(cls) -> Dict[str, Any]:
        """Returns observability metadata about the currently active catalog."""
        cat = cls.get_catalog()
        return {
            "version": cat.get("version"),
            "source": cat.get("source"),
            "loaded_at": cat.get("loaded_at"),
            "official_domains_count": len(cat.get("official_domains", set())),
            "sensitive_brands_count": len(cat.get("sensitive_brands", set())),
            "token_boundary_count": len(cat.get("token_boundary_keywords", {})),
        }
