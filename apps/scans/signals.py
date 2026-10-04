# apps/scans/signals.py
"""
Scan Pipeline Signals
─────────────────────
Post-save signals that keep denormalized counters and flags in sync.

Signals:
  1. update_user_counters     — increments User.scanned_links / detected_threats
  2. sync_blacklist_to_domain — syncs Domain.is_blacklisted when Blacklist changes
  3. sync_whitelist_to_domain — syncs Domain.is_whitelisted when WhitelistEntry changes
"""

import logging
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.db.models import F

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 1. User counters: scanned_links & detected_threats
# ══════════════════════════════════════════════════════════════════════════════

@receiver(post_save, sender='scans.Scan')
def update_user_counters(sender, instance, created, **kwargs):
    """
    After a Scan is created, increment the user's counters.
    Uses F() expressions for atomic, race-condition-safe updates.
    """
    if not created:
        return

    user = instance.user
    if not user:
        return  # Guest scan — no user to update

    try:
        update_fields = {'scanned_links': F('scanned_links') + 1}

        # If the scan detected a threat, also increment detected_threats
        if instance.final_verdict in ('malicious', 'suspicious'):
            update_fields['detected_threats'] = F('detected_threats') + 1

        from apps.accounts.models import User
        User.objects.filter(pk=user.pk).update(**update_fields)

        logger.debug(
            "[SIGNAL] Updated counters for user %s (verdict=%s)",
            user.email, instance.final_verdict
        )
    except Exception as e:
        # Never crash the scan pipeline for a counter update
        logger.warning("[SIGNAL] Failed to update user counters: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Blacklist ↔ Domain.is_blacklisted sync
# ══════════════════════════════════════════════════════════════════════════════

@receiver(post_save, sender='scans.Blacklist')
def sync_blacklist_to_domain_on_save(sender, instance, **kwargs):
    """
    When a Blacklist entry is created/updated, sync Domain.is_blacklisted
    and invalidate any cached scan results for this domain.
    """
    _sync_domain_blacklist_flag(instance)
    _invalidate_scan_cache_for_domain(instance.domain)


@receiver(post_delete, sender='scans.Blacklist')
def sync_blacklist_to_domain_on_delete(sender, instance, **kwargs):
    """
    When a Blacklist entry is deleted, recheck if the domain
    still has any active blacklist entries, and invalidate stale cache.
    """
    _sync_domain_blacklist_flag(instance, deleted=True)
    _invalidate_scan_cache_for_domain(instance.domain)


def _invalidate_scan_cache_for_domain(domain_name: str):
    """Invalidates all ScanCache entries containing the specified domain."""
    if not domain_name:
        return
    try:
        from apps.scans.models import ScanCache
        deleted_count, _ = ScanCache.objects.filter(url__icontains=domain_name).delete()
        if deleted_count > 0:
            logger.info("[SIGNAL] Invalidated %d ScanCache entries for domain %s", deleted_count, domain_name)
    except Exception as e:
        logger.warning("[SIGNAL] Failed to invalidate ScanCache for domain %s: %s", domain_name, e)


def _sync_domain_blacklist_flag(blacklist_entry, deleted=False):
    """Core sync logic for Blacklist → Domain.is_blacklisted."""
    from apps.domains.models import Domain
    from apps.scans.models import Blacklist

    domain_name = blacklist_entry.domain
    if not domain_name:
        return

    try:
        domain_obj = Domain.objects.filter(domain=domain_name).first()
        if not domain_obj:
            return  # Domain not tracked yet — nothing to sync

        # Check if ANY active blacklist entry exists for this domain
        has_active = Blacklist.objects.filter(
            domain=domain_name, is_active=True
        ).exists()

        if domain_obj.is_blacklisted != has_active:
            domain_obj.is_blacklisted = has_active
            domain_obj.save(update_fields=['is_blacklisted'])
            logger.info(
                "[SIGNAL] Domain %s → is_blacklisted=%s",
                domain_name, has_active
            )
    except Exception as e:
        logger.warning("[SIGNAL] Blacklist→Domain sync failed: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
# 3. WhitelistEntry ↔ Domain.is_whitelisted sync
# ══════════════════════════════════════════════════════════════════════════════

@receiver(post_save, sender='scans.WhitelistEntry')
def sync_whitelist_to_domain_on_save(sender, instance, **kwargs):
    """When a WhitelistEntry is created/updated, sync Domain.is_whitelisted."""
    _sync_domain_whitelist_flag(instance)


@receiver(post_delete, sender='scans.WhitelistEntry')
def sync_whitelist_to_domain_on_delete(sender, instance, **kwargs):
    """When a WhitelistEntry is deleted, recheck the domain."""
    _sync_domain_whitelist_flag(instance, deleted=True)


def _sync_domain_whitelist_flag(whitelist_entry, deleted=False):
    """Core sync logic for WhitelistEntry → Domain.is_whitelisted."""
    from apps.domains.models import Domain
    from apps.scans.models import WhitelistEntry

    domain_name = whitelist_entry.domain
    if not domain_name:
        return

    try:
        domain_obj = Domain.objects.filter(domain=domain_name).first()
        if not domain_obj:
            return

        has_active = WhitelistEntry.objects.filter(
            domain=domain_name, is_active=True
        ).exists()

        if domain_obj.is_whitelisted != has_active:
            domain_obj.is_whitelisted = has_active
            domain_obj.save(update_fields=['is_whitelisted'])
            logger.info(
                "[SIGNAL] Domain %s → is_whitelisted=%s",
                domain_name, has_active
            )
    except Exception as e:
        logger.warning("[SIGNAL] Whitelist→Domain sync failed: %s", e)
