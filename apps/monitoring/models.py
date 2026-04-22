# apps/monitoring/models.py
"""
Engine Health Monitoring
────────────────────────
Logs performance and availability of each scanning engine.
Enables dashboard alerts when engines degrade or fail.
"""

import uuid
from django.db import models
from django.conf import settings


class EngineHealthLog(models.Model):
    """
    Records the outcome of each engine invocation.
    Aggregated in the admin dashboard to show uptime and latency trends.
    """

    ENGINE_CHOICES = [
        ('gsb', 'Google Safe Browsing'),
        ('vt', 'VirusTotal'),
        ('domain_age', 'Domain Age (RDAP/WHOIS)'),
        ('typosquatting', 'Typosquatting Detection'),
        ('homoglyph', 'Homoglyph Detection'),
        ('phishing_patterns', 'Phishing Patterns'),
        ('url_features', 'URL Features'),
        ('dns', 'DNS Intelligence'),
        ('ssl', 'SSL Intelligence'),
        ('threat_intel', 'Threat Intelligence'),
        ('url_unshortener', 'URL Unshortener'),
        ('ai_model', 'AI Model'),
        ('bloom_filter', 'Bloom Filter'),
        ('blacklist', 'Blacklist Lookup'),
    ]

    STATUS_CHOICES = [
        ('ok', 'يعمل بشكل طبيعي'),
        ('degraded', 'أداء منخفض'),
        ('error', 'خطأ'),
        ('timeout', 'انتهت المهلة'),
        ('skipped', 'تم تجاوزه'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    engine_name = models.CharField(
        max_length=30, choices=ENGINE_CHOICES,
        verbose_name='المحرك')
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES,
        verbose_name='الحالة')
    latency_ms = models.FloatField(
        default=0.0, verbose_name='زمن الاستجابة (ms)')
    error_message = models.TextField(
        blank=True, verbose_name='رسالة الخطأ')
    scan_url = models.URLField(
        max_length=2000, blank=True,
        verbose_name='الرابط المفحوص')
    checked_at = models.DateTimeField(
        auto_now_add=True, verbose_name='وقت الفحص')

    class Meta:
        verbose_name = 'سجل صحة المحرك'
        verbose_name_plural = 'سجلات صحة المحركات'
        ordering = ['-checked_at']
        indexes = [
            models.Index(fields=['engine_name', '-checked_at']),
            models.Index(fields=['status']),
            models.Index(fields=['-checked_at']),
        ]

    def __str__(self):
        icon = '✅' if self.status == 'ok' else '⚠️' if self.status == 'degraded' else '❌'
        return f"{icon} {self.get_engine_name_display()} — {self.latency_ms:.0f}ms"


class AuditLog(models.Model):
    """
    Tracks administrative actions (e.g. adding to Blacklist/Whitelist, user role changes).
    """
    ACTION_CHOICES = [
        ('create', 'إنشاء'),
        ('update', 'تعديل'),
        ('delete', 'حذف'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True,
        verbose_name='المشرف', related_name='audit_logs')
    action = models.CharField(
        max_length=20, choices=ACTION_CHOICES, verbose_name='نوع الإجراء')
    resource_type = models.CharField(
        max_length=50, verbose_name='نوع المورد (Resource)')
    resource_id = models.CharField(
        max_length=255, null=True, blank=True, verbose_name='معرف المورد')
    details = models.TextField(
        null=True, blank=True, verbose_name='التفاصيل')
    ip_address = models.GenericIPAddressField(
        null=True, blank=True, verbose_name='IP المشرف')
    created_at = models.DateTimeField(
        auto_now_add=True, verbose_name='وقت الإجراء')

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'سجل تدقيق'
        verbose_name_plural = 'سجلات التدقيق'

    def __str__(self):
        return f"{self.user} -> {self.get_action_display()} {self.resource_type}"
