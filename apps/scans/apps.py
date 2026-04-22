# apps/scans/apps.py
from django.apps import AppConfig


class ScansConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.scans'
    verbose_name = 'الفحوصات'

    def ready(self):
        # Import signals to register them with Django's signal dispatcher
        import apps.scans.signals  # noqa: F401
