import os
from django.apps import AppConfig

class DomainsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.domains'
    verbose_name = 'استخبارات الدومينات'

    def ready(self):
        """
        Warms up the 17M domain whitelist during startup.
        Uses RUN_MAIN to ensure it only runs once in the development server.
        """
        import sys
        # prevents double loading in runserver
        # RUN_MAIN is set by the child process of runserver
        # If --noreload is used, RUN_MAIN is not set, but we still want to load
        if os.environ.get('RUN_MAIN') == 'true' or '--noreload' in sys.argv:
            try:
                from domain_analysis.services.bloom_filter import get_bloom
                print("SafeClick: Warming up 17M domain whitelist...")
                get_bloom() # This will build/load the filter blocking startup
                print("SafeClick: Whitelist ready. System is blazing fast.")
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to load bloom filter at startup: {e}")
