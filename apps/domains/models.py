# apps/domains/models.py
"""
Domain Intelligence Store
─────────────────────────
Central repository for all domain-related intelligence data.
Prevents redundant WHOIS/DNS/SSL lookups by caching domain metadata.

Design:
    - Domain: stores registration, SSL, DNS, and aggregate scan stats
    - DomainIntel: stores external threat intelligence feeds per domain
"""

import uuid
from django.db import models


class Domain(models.Model):
    """
    Central domain intelligence record.

    When a URL is scanned, we extract the registrable domain (e.g. google.com)
    and either fetch or create a Domain record.  All network-heavy lookups
    (WHOIS, RDAP, SSL handshake, DNS queries) are persisted here so subsequent
    scans of the same domain return instantly.

    Refresh policy:
        - Active domains (scanned in last 7 days): refresh every 7 days
        - Inactive domains: no automatic refresh
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.CharField(max_length=255, unique=True, db_index=True,
                              verbose_name='الدومين')

    # ── Registration Info (RDAP / WHOIS) ─────────────────────────────────
    registrar = models.CharField(max_length=255, null=True, blank=True,
                                 verbose_name='المسجّل')
    registration_date = models.DateTimeField(null=True, blank=True,
                                             verbose_name='تاريخ التسجيل')
    expiration_date = models.DateTimeField(null=True, blank=True,
                                           verbose_name='تاريخ الانتهاء')
    age_days = models.IntegerField(null=True, blank=True,
                                   verbose_name='العمر (أيام)')
    whois_country = models.CharField(max_length=10, null=True, blank=True,
                                     verbose_name='بلد التسجيل')

    # ── SSL / TLS Intelligence ───────────────────────────────────────────
    has_ssl = models.BooleanField(default=False, verbose_name='يملك SSL')
    ssl_issuer = models.CharField(max_length=255, null=True, blank=True,
                                  verbose_name='مصدر الشهادة')
    ssl_is_self_signed = models.BooleanField(default=False,
                                             verbose_name='شهادة ذاتية التوقيع')
    ssl_is_expired = models.BooleanField(default=False,
                                         verbose_name='شهادة منتهية')
    ssl_expiry_days = models.IntegerField(null=True, blank=True,
                                          verbose_name='أيام لانتهاء SSL')
    ssl_protocol = models.CharField(max_length=20, null=True, blank=True,
                                    verbose_name='بروتوكول SSL')

    # ── DNS Intelligence ─────────────────────────────────────────────────
    dns_resolves = models.BooleanField(default=False, verbose_name='DNS يعمل')
    dns_has_mx = models.BooleanField(default=False, verbose_name='يملك MX')
    dns_has_ns = models.BooleanField(default=False, verbose_name='يملك NS')
    dns_abnormal_config = models.BooleanField(default=False,
                                              verbose_name='إعدادات DNS غير طبيعية')
    dns_records = models.JSONField(default=dict, blank=True,
                                   verbose_name='سجلات DNS')

    # ── Classification ───────────────────────────────────────────────────
    is_whitelisted = models.BooleanField(default=False, db_index=True,
                                         verbose_name='في القائمة البيضاء')
    is_blacklisted = models.BooleanField(default=False, db_index=True,
                                         verbose_name='في القائمة السوداء')

    # ── Aggregate Stats ──────────────────────────────────────────────────
    total_scans = models.IntegerField(default=0, verbose_name='عدد الفحوصات')
    threat_detections = models.IntegerField(default=0,
                                            verbose_name='عدد اكتشافات التهديد')
    threat_ratio = models.FloatField(default=0.0,
                                     verbose_name='نسبة التهديد')

    # ── Timestamps ───────────────────────────────────────────────────────
    last_checked = models.DateTimeField(auto_now=True,
                                        verbose_name='آخر فحص')
    created_at = models.DateTimeField(auto_now_add=True,
                                      verbose_name='تاريخ الإنشاء')

    class Meta:
        verbose_name = 'دومين'
        verbose_name_plural = 'الدومينات'
        ordering = ['-last_checked']
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['is_blacklisted']),
            models.Index(fields=['is_whitelisted']),
            models.Index(fields=['-total_scans']),
            models.Index(fields=['-last_checked']),
        ]

    def __str__(self):
        status = '🔴' if self.is_blacklisted else '🟢' if self.is_whitelisted else '⚪'
        return f"{status} {self.domain} (age={self.age_days}d, scans={self.total_scans})"

    def update_threat_ratio(self):
        """Recalculate threat_ratio from aggregate stats."""
        if self.total_scans > 0:
            self.threat_ratio = round(self.threat_detections / self.total_scans, 4)
        else:
            self.threat_ratio = 0.0

    @property
    def safety_ratio(self):
        """Returns the inverted threat_ratio as safety ratio (1.0 = Safe, 0.0 = Malicious)"""
        if self.threat_ratio is None:
            return 1.0
        return max(0.0, min(1.0, 1.0 - float(self.threat_ratio)))


class DomainIntel(models.Model):
    """
    External threat intelligence entries linked to a domain.
    Sources: OpenPhish, PhishTank, user reports, manual review, etc.
    Multiple entries per domain are expected (one per source/sighting).
    """

    SEVERITY_CHOICES = [
        (1, 'منخفض'),
        (2, 'متوسط'),
        (3, 'عالي'),
        (4, 'خطير'),
        (5, 'حرج'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE,
                               related_name='intel_entries',
                               verbose_name='الدومين')
    intel_source = models.CharField(max_length=100, verbose_name='المصدر')
    threat_type = models.CharField(max_length=100, verbose_name='نوع التهديد')
    severity = models.IntegerField(choices=SEVERITY_CHOICES, default=3,
                                   verbose_name='الخطورة')
    details = models.JSONField(default=dict, blank=True,
                               verbose_name='التفاصيل')
    first_seen = models.DateTimeField(auto_now_add=True,
                                      verbose_name='أول مشاهدة')
    last_seen = models.DateTimeField(auto_now=True,
                                     verbose_name='آخر مشاهدة')

    class Meta:
        verbose_name = 'معلومة استخباراتية'
        verbose_name_plural = 'المعلومات الاستخباراتية'
        indexes = [
            models.Index(fields=['domain', 'intel_source']),
            models.Index(fields=['threat_type']),
        ]

    def __str__(self):
        return f"{self.domain.domain} — {self.intel_source}: {self.threat_type}"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Dynamic Brand Catalog & Domain Intelligence
# ══════════════════════════════════════════════════════════════════════════════

class Brand(models.Model):
    """
    Sensitive Brand Catalog Entity.
    Central record for brands vulnerable to impersonation and phishing.
    """
    SECTOR_CHOICES = [
        ('banking', 'بنوك ومصارف'),
        ('fintech', 'تقنية مالية ومدفوعات'),
        ('government', 'منصات حكومية وسيادية'),
        ('telecom', 'اتصالات وإنترنت'),
        ('ecommerce', 'تجارة إلكترونية وتوصيل'),
        ('tech', 'تكنولوجيا وسحابة'),
        ('crypto', 'عملات رقمية ومحافظ'),
        ('delivery', 'شحن وخدمات لوجستية'),
        ('other', 'قطاعات أخرى'),
    ]

    RISK_WEIGHT_CHOICES = [
        ('CRITICAL', 'حرج للغاية (2.0)'),
        ('HIGH', 'عالي الخطورة (1.5)'),
        ('MEDIUM', 'متوسط الخطورة (1.0)'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, verbose_name='اسم العلامة (EN)')
    name_ar = models.CharField(max_length=255, blank=True, verbose_name='اسم العلامة (AR)')
    slug = models.SlugField(max_length=100, unique=True, db_index=True, verbose_name='المعرف الفريد (Slug)')
    sector = models.CharField(max_length=50, choices=SECTOR_CHOICES, default='banking', verbose_name='القطاع')
    country = models.CharField(max_length=10, default='SA', verbose_name='الدولة', help_text='SA, EG, AE, GLOBAL...')
    risk_weight = models.CharField(max_length=20, choices=RISK_WEIGHT_CHOICES, default='HIGH', verbose_name='وزن الحساسية')
    is_active = models.BooleanField(default=True, db_index=True, verbose_name='نشط')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='تاريخ الإنشاء')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='آخر تحديث')

    class Meta:
        verbose_name = 'علامة تجارية / جهة'
        verbose_name_plural = 'كتالوج العلامات والجهات المعتمدة'
        ordering = ['name']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['sector']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        flag = '🟢' if self.is_active else '⚪'
        return f"{flag} {self.name} ({self.name_ar or self.slug}) - {self.get_sector_display()}"


class BrandDomain(models.Model):
    """
    Official verified domain(s) belonging to a Brand.
    Canonical source of truth for legitimate brand domains (Anti-Phishing Baseline).
    """
    STATUS_CHOICES = [
        ('VERIFIED', 'معتمد وموثق'),
        ('PENDING', 'قيد التحقق والمراجعة'),
        ('DEPRECATED', 'ملغى أو قديم'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    brand = models.ForeignKey(Brand, on_delete=models.CASCADE, related_name='domains', verbose_name='العلامة التجارية')
    domain = models.CharField(max_length=255, unique=True, db_index=True, verbose_name='النطاق الرسمي', help_text='مثال: alrajhibank.com.sa')
    is_primary = models.BooleanField(default=False, verbose_name='النطاق الأساسي')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='VERIFIED', db_index=True, verbose_name='حالة التحقق')
    verification_source = models.CharField(max_length=100, default='MANUAL_AUDIT', verbose_name='مصدر التوثيق')
    verified_at = models.DateTimeField(null=True, blank=True, verbose_name='تاريخ التوثيق')
    is_active = models.BooleanField(default=True, db_index=True, verbose_name='نشط')
    notes = models.TextField(blank=True, verbose_name='ملاحظات')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='تاريخ الإضافة')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='آخر تحديث')

    class Meta:
        verbose_name = 'نطاق رسمي معتمد'
        verbose_name_plural = 'النطاقات الرسمية المعتمدة'
        ordering = ['domain']
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['status', 'is_active']),
        ]

    def clean(self):
        if self.domain:
            d = self.domain.strip().lower()
            if "://" in d:
                d = d.split("://", 1)[1]
            d = d.split("/")[0].split("?")[0].rstrip(".")
            self.domain = d

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        badge = '✅' if (self.status == 'VERIFIED' and self.is_active) else '⏳'
        return f"{badge} {self.domain} → {self.brand.name}"


class BrandKeyword(models.Model):
    """
    Keywords, abbreviations, and patterns representing the Brand in URLs/Domains.
    """
    STRATEGY_CHOICES = [
        ('TOKEN_BOUNDARY', 'حدود الكلمات المنفصلة (للاختصارات والأسماء القصيرة مثل snb, cib)'),
        ('TYPO_SIMILARITY', 'تشابه إملائي وتصحيف لاتيني (مثل alrajhibank)'),
        ('CONTAINS', 'احتواء نصي صريح (للأسماء الفريدة الطويلة فقط)'),
        ('EXACT', 'مطابقة تامة لكامل الدومين الرئيسي'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    brand = models.ForeignKey(Brand, on_delete=models.CASCADE, related_name='keywords', verbose_name='العلامة التجارية')
    keyword = models.CharField(max_length=100, db_index=True, verbose_name='الكلمة المفتاحية', help_text='مثال: snb, alrajhi, alrajhibank')
    match_strategy = models.CharField(max_length=30, choices=STRATEGY_CHOICES, default='TOKEN_BOUNDARY', verbose_name='استراتيجية المطابقة')
    weight = models.FloatField(default=1.0, verbose_name='وزن الثقة (0.1 - 1.0)')
    is_active = models.BooleanField(default=True, db_index=True, verbose_name='نشط')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='تاريخ الإضافة')

    class Meta:
        verbose_name = 'كلمة مفتاحية للبراند'
        verbose_name_plural = 'الكلمات المفتاحية للبراندات'
        unique_together = ['brand', 'keyword']
        indexes = [
            models.Index(fields=['keyword']),
            models.Index(fields=['match_strategy']),
            models.Index(fields=['is_active']),
        ]

    def clean(self):
        if self.keyword:
            self.keyword = self.keyword.strip().lower()

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.keyword} ({self.get_match_strategy_display()}) → {self.brand.name}"

