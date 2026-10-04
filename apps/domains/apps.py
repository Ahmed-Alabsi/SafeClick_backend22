import os
from django.apps import AppConfig

class DomainsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.domains'
    verbose_name = 'استخبارات الدومينات'

    def ready(self):
        """
        Warms up the 17M domain whitelist during startup and connects signals.
        """
        import sys

        # Connect signals
        try:
            import apps.domains.signals  # noqa
        except Exception:
            pass

        # prevents double loading in runserver
        # RUN_MAIN is set by the child process of runserver
        # If --noreload is used, RUN_MAIN is not set, but we still want to load
        if os.environ.get('RUN_MAIN') == 'true' or '--noreload' in sys.argv:
            import logging
            logger = logging.getLogger(__name__)
            try:
                from domain_analysis.services.bloom_filter import get_bloom
                logger.info("SafeClick: Warming up 17M domain whitelist...")
                get_bloom() # This will build/load the filter blocking startup
                logger.info("SafeClick: Whitelist ready. System is blazing fast.")
            except Exception as e:
                logger.error(f"Failed to load bloom filter at startup: {e}")

