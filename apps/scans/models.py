# apps/scans/models.py
"""
Scan Models — v2.0
──────────────────
Restructured scan models with:
  - Deduplicated Scan (removed score/timestamp duplicates)
  - ScanSourceResult with source_weight for weighted aggregation
  - Improved Blacklist with is_active, expires_at, description
  - ScanCache with scan_level support for Priority Cache
"""

import uuid
from django.db import models
from django.conf import settings


class Scan(models.Model):
    """
    Core scan record — one per URL scan request.

    v2.0 changes:
      - Removed duplicate fields (score, timestamp)
      - Added scan_level to track which scan depth was used
      - Added domain FK to link to Domain intelligence table
      - Individual source results moved to ScanSourceResult
    """

    SCAN_LEVEL_CHOICES = [
        ('basic', 'فحص سريع'),
        ('standard', 'فحص متوازن'),
        ('deep', 'فحص عميق'),
    ]

    VERDICT_CHOICES = [
        ('safe', 'آمن'),
        ('suspicious', 'مشبوه'),
        ('malicious', 'خطير'),
        ('error', 'خطأ'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='scans', null=True, blank=True,
        verbose_name='المستخدم')
    guest_id = models.UUIDField(
        db_index=True, null=True, blank=True,
        verbose_name='معرّف الزائر')

    # ── URL Info ─────────────────────────────────────────────────────────
    url = models.URLField(max_length=2000, verbose_name='الرابط')
    url_hash = models.CharField(
        max_length=64, db_index=True, null=True, blank=True,
        verbose_name='هاش الرابط')
    domain_name = models.CharField(
        max_length=255, db_index=True, null=True, blank=True,
        verbose_name='اسم الدومين')
    domain = models.ForeignKey(
        'domains.Domain', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='scans',
        verbose_name='الدومين')
    ip_address = models.GenericIPAddressField(
        null=True, blank=True, verbose_name='عنوان IP')

    # ── Scan Configuration ───────────────────────────────────────────────
    scan_level = models.CharField(
        max_length=20, choices=SCAN_LEVEL_CHOICES, default='basic',
        verbose_name='مستوى الفحص')

    # ── Final Result (aggregated from all sources) ───────────────────────
    final_verdict = models.CharField(
        max_length=20, choices=VERDICT_CHOICES, null=True, blank=True,
        verbose_name='الحكم النهائي')
    risk_score = models.IntegerField(
        default=0, verbose_name='درجة الخطورة')

    # ── Scenario Engine Fields ───────────────────────────────────────────
    scan_scenario = models.CharField(
        max_length=50, null=True, blank=True,
        verbose_name='سيناريو الفحص')
    reason = models.TextField(
        null=True, blank=True,
        verbose_name='سبب النتيجة')

    # Legacy compatibility fields (for Flutter frontend)
    safe = models.BooleanField(null=True, verbose_name='آمن')
    result = models.CharField(
        max_length=50, null=True, blank=True,
        verbose_name='النتيجة النصية')
    score = models.IntegerField(
        default=0, verbose_name='النقاط (legacy)')

    # ── Scan Metadata ────────────────────────────────────────────────────
    source = models.CharField(
        max_length=100, default='system', verbose_name='المصدر')
    details = models.JSONField(
        default=list, verbose_name='التفاصيل')
    threats_found = models.JSONField(
        default=list, verbose_name='التهديدات المكتشفة')
    threats_count = models.IntegerField(
        default=0, verbose_name='عدد التهديدات')
    response_time = models.FloatField(
        default=0, verbose_name='زمن الاستجابة')
    server_info = models.CharField(
        max_length=255, null=True, blank=True,
        verbose_name='معلومات السيرفر')
    engines_used = models.JSONField(
        default=list, blank=True,
        verbose_name='المحركات المستخدمة')

    # ── Timestamps ───────────────────────────────────────────────────────
    created_at = models.DateTimeField(
        auto_now_add=True, verbose_name='تاريخ الإنشاء')
    updated_at = models.DateTimeField(
        auto_now=True, verbose_name='آخر تحديث')
    deleted_at = models.DateTimeField(
        null=True, blank=True, verbose_name='تاريخ الحذف')

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'فحص'
        verbose_name_plural = 'الفحوصات'
        indexes = [
            models.Index(fields=['url_hash']),
            models.Index(fields=['domain_name']),
            models.Index(fields=['created_at']),
            models.Index(fields=['scan_level']),
            models.Index(fields=['final_verdict']),
        ]

    def __str__(self):
        status = 'آمن' if self.safe is True else 'خطير' if self.safe is False else 'مشبوه'
        return f"{self.url[:50]} — {status} ({self.risk_score}%)"

    # Legacy property for backward compat
    @property
    def timestamp(self):
        return self.created_at

    @property
    def safety_score(self):
        """Returns the inverted risk_score as safety percentage (100 = Safe, 0 = Malicious)"""
        if self.risk_score is None:
            return 100
        return max(0, min(100, 100 - self.risk_score))


class ScanSourceResult(models.Model):
    """
    Individual result from each scanning source.

    One Scan has 1–N ScanSourceResults (one per active source).
    Each result carries a source_weight for weighted aggregation:

        Final Score = Σ(risk_score × source_weight × confidence)
                    / Σ(source_weight × confidence)
    """

    SOURCE_TYPES = [
        ('gsb', 'Google Safe Browsing'),
        ('vt', 'VirusTotal'),
        ('engines', 'محركات داخلية'),
        ('ai', 'نموذج AI'),
        ('blacklist', 'القائمة السوداء'),
        ('whitelist', 'القائمة البيضاء'),
        ('heuristic', 'تحليل أولي'),
    ]

    VERDICT_CHOICES = [
        ('safe', 'آمن'),
        ('suspicious', 'مشبوه'),
        ('malicious', 'خطير'),
        ('error', 'خطأ'),
        ('skipped', 'تم تجاوزه'),
    ]

    # Default trust weights per source
    DEFAULT_WEIGHTS = {
        'blacklist': 0.95,
        'gsb': 0.90,
        'vt': 0.85,
        'engines': 0.80,
        'ai': 0.70,
        'whitelist': 0.90,
        'heuristic': 0.50,
    }

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(
        Scan, on_delete=models.CASCADE, related_name='source_results',
        verbose_name='الفحص')
    source_type = models.CharField(
        max_length=20, choices=SOURCE_TYPES,
        verbose_name='نوع المصدر')
    verdict = models.CharField(
        max_length=20, choices=VERDICT_CHOICES,
        verbose_name='الحكم')
    risk_score = models.IntegerField(
        default=0, verbose_name='درجة الخطورة')
    confidence = models.FloatField(
        default=0.0,
        verbose_name='الثقة',
        help_text='0.0 – 1.0: ثقة المصدر في نتيجته')
    source_weight = models.FloatField(
        default=0.80,
        verbose_name='وزن المصدر',
        help_text='وزن هذا المصدر في النتيجة النهائية')
    raw_data = models.JSONField(
        default=dict, verbose_name='البيانات الخام')
    latency_ms = models.FloatField(
        default=0.0, verbose_name='زمن الاستجابة (ms)')
    checked_at = models.DateTimeField(
        auto_now_add=True, verbose_name='وقت الفحص')

    class Meta:
        verbose_name = 'نتيجة مصدر فحص'
        verbose_name_plural = 'نتائج مصادر الفحص'
        indexes = [
            models.Index(fields=['scan', 'source_type']),
            models.Index(fields=['source_type', 'verdict']),
        ]
        unique_together = ['scan', 'source_type']

    def __str__(self):
        return f"{self.get_source_type_display()} → {self.verdict} ({self.risk_score}%)"

    def save(self, *args, **kwargs):
        # Auto-set default weight if not explicitly provided
        if not self.source_weight or self.source_weight == 0.80:
            self.source_weight = self.DEFAULT_WEIGHTS.get(
                self.source_type, 0.80)
        super().save(*args, **kwargs)



class Blacklist(models.Model):
    """
    Blocked URLs/domains list.

    v2.0 changes:
      - Added domain FK to Domain table
      - Added description (was missing but used in confirm_threat)
      - Added is_active and expires_at for lifecycle management
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain_ref = models.ForeignKey(
        'domains.Domain', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='blacklist_entries',
        verbose_name='مرجع الدومين')
    link = models.URLField(max_length=2000, unique=True, verbose_name='الرابط')
    domain = models.CharField(
        max_length=255, verbose_name='الدومين')
    threat_type = models.CharField(
        max_length=100, verbose_name='نوع التهديد')
    threat_category = models.CharField(
        max_length=100, blank=True, default='',
        verbose_name='تصنيف التهديد')
    severity = models.IntegerField(
        default=3, verbose_name='درجة الخطورة')
    description = models.TextField(
        blank=True, default='',
        verbose_name='الوصف')
    source = models.CharField(
        max_length=100, default='system', verbose_name='المصدر')
    is_active = models.BooleanField(
        default=True, db_index=True, verbose_name='نشط')
    added_at = models.DateTimeField(
        auto_now_add=True, verbose_name='تاريخ الإضافة')
    expires_at = models.DateTimeField(
        null=True, blank=True, verbose_name='تاريخ الانتهاء')

    class Meta:
        verbose_name = 'رابط محظور'
        verbose_name_plural = 'الروابط المحظورة'
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        active = '🟢' if self.is_active else '🔴'
        return f"{active} {self.domain} — {self.threat_type}"


class ScanCache(models.Model):
    """
    Server-side URL result cache (L2 layer).

    v2.0 changes:
      - Added scan_level to support Priority Cache (deep > standard > basic)
      - Added source_results JSON for quick reconstruction
      - Cache key is now (url_hash, scan_level) composite

    Priority Cache Logic:
      When requesting a basic scan, if a deep result exists and hasn't expired,
      return the deep result (it's strictly more comprehensive).
    """

    url_hash = models.CharField(max_length=64, db_index=True,
                                 verbose_name='هاش الرابط')
    url = models.URLField(max_length=2000, verbose_name='الرابط')
    scan_level = models.CharField(
        max_length=20, default='basic',
        verbose_name='مستوى الفحص')
    result = models.CharField(
        max_length=50, verbose_name='النتيجة')
    threat_level = models.CharField(
        max_length=20, default='none',
        verbose_name='مستوى التهديد')
    risk_score = models.IntegerField(
        default=0, verbose_name='درجة الخطورة')
    scan_scenario = models.CharField(
        max_length=50, null=True, blank=True,
        verbose_name='سيناريو الفحص')
    reason = models.TextField(
        null=True, blank=True,
        verbose_name='سبب النتيجة')
    source_results = models.JSONField(
        default=list, blank=True,
        verbose_name='نتائج المصادر')
    scanned_at = models.DateTimeField(
        auto_now_add=True, verbose_name='تاريخ الفحص')
    expires_at = models.DateTimeField(
        verbose_name='تاريخ الانتهاء')

    class Meta:
        verbose_name = 'كاش الروابط'
        verbose_name_plural = 'كاش الروابط'
        unique_together = ['url_hash', 'scan_level']
        indexes = [
            models.Index(fields=['url_hash', 'scan_level']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"{self.url[:60]} [{self.result}] {self.scan_level} expires={self.expires_at}"


class WhitelistEntry(models.Model):
    """
    Database-backed whitelist for admin-managed trusted domains.

    Supplements the static Bloom Filter (17M domains) with a dynamic layer
    that admins can manage from the Django admin panel.

    Lookup order in Phase 1:
        1. Blacklist DB check (instant block)
        2. Bloom Filter (17M static domains)
        3. WhitelistEntry DB check (dynamic admin-managed trust)
    """

    SOURCE_CHOICES = [
        ('admin', 'إضافة يدوية'),
        ('auto_verified', 'تحقق تلقائي'),
        ('scan_history', 'من سجل الفحوصات'),
        ('bloom_promoted', 'ترقية من Bloom Filter'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.CharField(
        max_length=255, unique=True, db_index=True,
        verbose_name='الدومين',
        help_text='مثال: google.com — بدون http:// أو www')
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, verbose_name='أضافه')
    reason = models.TextField(
        blank=True, verbose_name='سبب الإضافة',
        help_text='لماذا تم إضافة هذا الدومين إلى القائمة البيضاء')
    source = models.CharField(
        max_length=50, choices=SOURCE_CHOICES, default='admin',
        verbose_name='المصدر')
    is_active = models.BooleanField(
        default=True, db_index=True,
        verbose_name='نشط')
    notes = models.TextField(
        blank=True, verbose_name='ملاحظات إضافية')

    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True, verbose_name='تاريخ الإضافة')
    updated_at = models.DateTimeField(
        auto_now=True, verbose_name='آخر تحديث')
    expires_at = models.DateTimeField(
        null=True, blank=True,
        verbose_name='تاريخ الانتهاء',
        help_text='اتركه فارغاً ليكون دائماً')

    class Meta:
        verbose_name = 'دومين موثوق'
        verbose_name_plural = 'الدومينات الموثوقة (القائمة البيضاء)'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['is_active']),
            models.Index(fields=['-created_at']),
            models.Index(fields=['source']),
        ]

    def __str__(self):
        active = '🟢' if self.is_active else '🔴'
        return f"{active} {self.domain} ({self.get_source_display()})"
