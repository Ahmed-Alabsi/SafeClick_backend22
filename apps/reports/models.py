# apps/reports/models.py
"""
Report Management System — v2.0
────────────────────────────────
Added:
  - domain FK to Domain intelligence table
  - subcategory for detailed threat classification
  - assigned_to for admin workflow
  - 'investigating' and 'duplicate' status options
  - ReportStatusLog for audit trail
"""

import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone


class Report(models.Model):
    """نموذج البلاغات"""
    STATUS_CHOICES = [
        ('pending', 'جديد — قيد المراجعة'),
        ('reviewing', 'قيد المراجعة الأولية'),
        ('investigating', 'قيد التحقيق العميق'),
        ('confirmed', 'تهديد مؤكد'),
        ('rejected', 'بلاغ مرفوض'),
        ('resolved', 'تم الحل'),
        ('duplicate', 'مكرر'),
    ]

    SEVERITY_CHOICES = [
        (1, 'منخفض'),
        (2, 'متوسط'),
        (3, 'عالي'),
        (4, 'خطير'),
        (5, 'حرج'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='reports'
    )

    # ── URL & Domain Info ────────────────────────────────────────────────
    link = models.URLField(max_length=2000, verbose_name='الرابط المشبوه')
    domain_ref = models.ForeignKey(
        'domains.Domain', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='reports',
        verbose_name='مرجع الدومين')
    category = models.CharField(max_length=100, verbose_name='نوع التهديد')
    subcategory = models.CharField(
        max_length=100, blank=True, default='',
        verbose_name='التصنيف الفرعي')
    description = models.TextField(blank=True, verbose_name='وصف إضافي')
    severity = models.IntegerField(
        choices=SEVERITY_CHOICES, default=3, verbose_name='درجة الخطورة')

    # ── Status & Workflow ────────────────────────────────────────────────
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='pending',
        verbose_name='الحالة')
    tracking_number = models.CharField(
        max_length=50, unique=True, null=True, blank=True,
        verbose_name='رقم التتبع')
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='assigned_reports',
        verbose_name='المشرف المسؤول')

    # ── Reporter Info ────────────────────────────────────────────────────
    reporter_name = models.CharField(max_length=255, verbose_name='اسم المبلغ')
    reporter_email = models.EmailField(
        null=True, blank=True, verbose_name='البريد الإلكتروني للمبلغ')
    is_anonymous = models.BooleanField(
        default=False, verbose_name='بلغ بشكل مجهول')

    # ── Investigation ────────────────────────────────────────────────────
    investigation_notes = models.TextField(
        blank=True, verbose_name='ملاحظات التحقيق')
    is_confirmed_threat = models.BooleanField(
        default=False, verbose_name='تهديد مؤكد')
    community_votes = models.IntegerField(
        default=0, verbose_name='تصويتات المجتمع')
    priority = models.IntegerField(
        default=0, verbose_name='الأولوية',
        help_text='يُحسب تلقائياً بناءً على الخطورة وعدد البلاغات المشابهة')

    # ── Timestamps ───────────────────────────────────────────────────────
    created_at = models.DateTimeField(
        auto_now_add=True, verbose_name='تاريخ الإبلاغ')
    updated_at = models.DateTimeField(
        auto_now=True, verbose_name='آخر تحديث')
    reviewed_at = models.DateTimeField(
        null=True, blank=True, verbose_name='تاريخ المراجعة')
    resolved_at = models.DateTimeField(
        null=True, blank=True, verbose_name='تاريخ الحل')
    deleted_at = models.DateTimeField(
        null=True, blank=True,
        verbose_name='تاريخ الحذف من قبل المستخدم')

    class Meta:
        verbose_name = 'بلاغ'
        verbose_name_plural = 'البلاغات'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['tracking_number']),
            models.Index(fields=['severity']),
            models.Index(fields=['priority']),
        ]

    def __str__(self):
        return f"{self.tracking_number or 'بلاغ'} - {self.link[:50]}"

    @property
    def url(self):
        return self.link

    @property
    def reason(self):
        return self.category

    def save(self, *args, **kwargs):
        if not self.tracking_number:
            self.tracking_number = self._generate_tracking_number()
        super().save(*args, **kwargs)

    def _generate_tracking_number(self):
        """توليد رقم تتبع فريد وآمن تشفيرياً (CSPRNG)"""
        import secrets

        prefix = 'RPT'
        timestamp = timezone.now().strftime('%y%m%d')
        random_part = secrets.token_hex(4).upper()

        return f"{prefix}-{timestamp}-{random_part}"

    def _log_status_change(self, old_status, new_status, changed_by=None, notes=""):
        """Record status change in audit log."""
        ReportStatusLog.objects.create(
            report=self,
            changed_by=changed_by,
            old_status=old_status,
            new_status=new_status,
            notes=notes,
        )

    def confirm_threat(self, notes="", changed_by=None):
        """تأكيد التهديد وإضافته للقائمة السوداء"""
        old_status = self.status
        self.status = 'confirmed'
        self.is_confirmed_threat = True
        self.investigation_notes = notes
        self.reviewed_at = timezone.now()
        self.save()

        self._log_status_change(old_status, 'confirmed', changed_by, notes)

        # إضافة للقائمة السوداء
        from apps.scans.models import Blacklist
        import tldextract

        extracted = tldextract.extract(self.link)
        domain = f"{extracted.domain}.{extracted.suffix}"

        Blacklist.objects.get_or_create(
            link=self.link,
            defaults={
                'domain': domain,
                'threat_type': self.category,
                'severity': self.severity,
                'description': self.description or 'تم الإبلاغ عنه وتأكيده',
                'source': 'user_report'
            }
        )

    def reject_report(self, notes="", changed_by=None):
        """رفض البلاغ"""
        old_status = self.status
        self.status = 'rejected'
        self.investigation_notes = notes
        self.reviewed_at = timezone.now()
        self.save()
        self._log_status_change(old_status, 'rejected', changed_by, notes)

    def resolve_report(self, notes="", changed_by=None):
        """حل البلاغ"""
        old_status = self.status
        self.status = 'resolved'
        self.investigation_notes = notes
        self.resolved_at = timezone.now()
        self.save()
        self._log_status_change(old_status, 'resolved', changed_by, notes)


class ReportComment(models.Model):
    """تعليقات على البلاغات"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(
        Report, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)

    content = models.TextField(verbose_name='محتوى التعليق')
    is_internal = models.BooleanField(
        default=False, verbose_name='داخلي (للمشرفين فقط)')

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"تعليق على {self.report.tracking_number}"


class ReportStatusLog(models.Model):
    """
    Audit trail for report status changes.
    Records who changed the status, when, and why.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(
        Report, on_delete=models.CASCADE, related_name='status_logs',
        verbose_name='البلاغ')
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, verbose_name='من قام بالتغيير')
    old_status = models.CharField(
        max_length=20, verbose_name='الحالة السابقة')
    new_status = models.CharField(
        max_length=20, verbose_name='الحالة الجديدة')
    notes = models.TextField(
        blank=True, verbose_name='ملاحظات')
    changed_at = models.DateTimeField(
        auto_now_add=True, verbose_name='وقت التغيير')

    class Meta:
        verbose_name = 'سجل تغيير حالة'
        verbose_name_plural = 'سجلات تغيير الحالات'
        ordering = ['-changed_at']
        indexes = [
            models.Index(fields=['report', '-changed_at']),
        ]

    def __str__(self):
        return f"{self.report.tracking_number}: {self.old_status} → {self.new_status}"