# apps/domains/signals.py
"""
Domain Intelligence Signals
───────────────────────────
Keeps the in-memory brand intelligence cache synchronized with database updates.
Uses transaction.on_commit() to ensure cache version is bumped ONLY after DB commit.
"""

import logging
from django.db import transaction
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

logger = logging.getLogger(__name__)


def _trigger_catalog_version_bump():
    """Triggers atomic catalog version bump in BrandService."""
    try:
        from apps.domains.services.brand_service import BrandService
        BrandService.bump_version()
    except Exception as e:
        logger.warning(f"[SIGNAL] Failed to bump brand catalog version: {e}")


@receiver(post_save, sender='domains.Brand')
@receiver(post_delete, sender='domains.Brand')
@receiver(post_save, sender='domains.BrandDomain')
@receiver(post_delete, sender='domains.BrandDomain')
@receiver(post_save, sender='domains.BrandKeyword')
@receiver(post_delete, sender='domains.BrandKeyword')
def handle_brand_catalog_change(sender, **kwargs):
    """
    When any Brand, BrandDomain, or BrandKeyword is created, updated, or deleted,
    safely bump the catalog version inside transaction.on_commit().
    """
    transaction.on_commit(_trigger_catalog_version_bump)
