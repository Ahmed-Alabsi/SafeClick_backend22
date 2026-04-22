# apps/domains/services/domain_service.py
"""
Domain Service
──────────────
Provides functionality to lookup domain intelligence from the Domain model,
and fetch external data (WHOIS/SSL/DNS) if missing or expired.
"""

from django.utils import timezone
from datetime import timedelta
import logging
from apps.domains.models import Domain
from domain_analysis.services.domain_utils import extract_domain

logger = logging.getLogger(__name__)

class DomainService:
    @staticmethod
    def get_or_fetch_domain(url: str) -> Domain:
        """
        Retrieves domain record. If it doesn't exist or is older than 7 days,
        can trigger a background refresh of WHOIS/SSL info.
        """
        domain_name = extract_domain(url)
        if not domain_name:
            return None
            
        domain_obj, created = Domain.objects.get_or_create(domain=domain_name)
        
        # If it's a new domain or data is stale (> 7 days), we refresh.
        stale_threshold = timezone.now() - timedelta(days=7)
        if created or (domain_obj.last_checked and domain_obj.last_checked < stale_threshold):
            # In a real heavy system this would dispatch a Celery task.
            # We do a quick background fetch using threading for now.
            import threading
            threading.Thread(target=DomainService._fetch_intel_background, args=(domain_obj.id,)).start()
            
        return domain_obj

    @staticmethod
    def _fetch_intel_background(domain_id: str):
        """Fetches WHOIS, SSL, DNS records asynchronously."""
        try:
            domain_obj = Domain.objects.get(id=domain_id)
            
            # Here we integrate with the previous RDAP/SSL modules.
            from domain_analysis.services.rdap_client import RDAPClient
            rdap = RDAPClient()
            info = rdap.get_domain_info(domain_obj.domain)
            
            if info:
                domain_obj.registrar = info.get('registrar')
                domain_obj.registration_date = info.get('creation_date')
                domain_obj.expiration_date = info.get('expiration_date')
                # calculate age...
            
            # We skip actual heavy SSL/DNS checks in this scaffolding.
            domain_obj.save()
            logger.info(f"Refreshed background intelligence for {domain_obj.domain}")
        except Exception as e:
            logger.error(f"Error fetching background intel for domain {domain_id}: {e}")
