# apps/ai/models.py
"""
AI Model Management System
───────────────────────────
Manages the lifecycle of ML models used for phishing detection:
  - AIModelVersion: tracks each trained model with metrics
  - AITrainingDataset: enriched training samples with feature versioning
  - AIPrediction: records every prediction for auditing & feedback loop
"""

import uuid
from django.db import models
from django.conf import settings


# ── Current Feature Schema ───────────────────────────────────────────────
# Increment this when adding/removing/renaming features.
# Old training data with a different version must be migrated or excluded.
CURRENT_FEATURE_SCHEMA_VERSION = 1


class AIModelVersion(models.Model):
    """
    Tracks each trained model version with performance metrics.

    Lifecycle:  training → validating → ready → deployed → archived
    Only ONE model can be 'deployed' at a time (enforced in application logic).
    """

    STATUS_CHOICES = [
        ('training', 'قيد التدريب'),
        ('validating', 'قيد التحقق'),
        ('ready', 'جاهز'),
        ('deployed', 'مُفعّل'),
        ('archived', 'مؤرشف'),
    ]

    ALGORITHM_CHOICES = [
        ('xgboost', 'XGBoost'),
        ('random_forest', 'Random Forest'),
        ('lightgbm', 'LightGBM'),
        ('neural_net', 'Neural Network'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    model_name = models.CharField(
        max_length=100, default='safeclick_phishing_detector',
        verbose_name='اسم النموذج')
    version = models.CharField(
        max_length=20, unique=True, verbose_name='الإصدار')  # e.g. "v1.0.0"
    algorithm = models.CharField(
        max_length=50, choices=ALGORITHM_CHOICES, default='xgboost',
        verbose_name='الخوارزمية')

    # ── Performance Metrics ──────────────────────────────────────────────
    accuracy = models.FloatField(default=0.0, verbose_name='الدقة')
    precision_score = models.FloatField(default=0.0, verbose_name='Precision')
    recall = models.FloatField(default=0.0, verbose_name='Recall')
    f1_score = models.FloatField(default=0.0, verbose_name='F1 Score')
    auc_roc = models.FloatField(default=0.0, verbose_name='AUC-ROC')

    # ── Training Info ────────────────────────────────────────────────────
    training_samples = models.IntegerField(default=0,
                                           verbose_name='عينات التدريب')
    feature_schema_version = models.IntegerField(
        default=CURRENT_FEATURE_SCHEMA_VERSION,
        verbose_name='إصدار schema الخصائص')
    model_file_path = models.CharField(
        max_length=500, blank=True, verbose_name='مسار ملف النموذج')
    hyperparameters = models.JSONField(
        default=dict, blank=True, verbose_name='المعاملات الفائقة')
    feature_importance = models.JSONField(
        default=dict, blank=True, verbose_name='أهمية الخصائص')
    feature_list = models.JSONField(
        default=list, blank=True,
        verbose_name='قائمة الخصائص المستخدمة')

    # ── Status ───────────────────────────────────────────────────────────
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='training',
        verbose_name='الحالة')
    notes = models.TextField(blank=True, verbose_name='ملاحظات')

    # ── Timestamps ───────────────────────────────────────────────────────
    trained_at = models.DateTimeField(null=True, blank=True,
                                      verbose_name='تاريخ التدريب')
    deployed_at = models.DateTimeField(null=True, blank=True,
                                       verbose_name='تاريخ التفعيل')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'إصدار نموذج AI'
        verbose_name_plural = 'إصدارات نماذج AI'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.model_name} {self.version} [{self.status}] " \
               f"(F1={self.f1_score:.2f})"


class AITrainingDataset(models.Model):
    """
    Enriched training sample with pre-computed features.

    Design decisions:
        - features stored as JSON for schema flexibility
        - feature_schema_version enables safe model upgrades
        - is_verified distinguishes auto-labeled from human-verified samples
        - export_ready_at marks samples ready for the next training cycle
    """

    LABEL_CHOICES = [
        ('safe', 'آمن'),
        ('phishing', 'تصيّد'),
        ('malware', 'برمجيات خبيثة'),
        ('suspicious', 'مشبوه'),
    ]

    SOURCE_CHOICES = [
        ('scan_history', 'سجل الفحوصات'),
        ('user_report', 'بلاغ مستخدم'),
        ('openphish', 'OpenPhish Feed'),
        ('phishtank', 'PhishTank Feed'),
        ('manual', 'إدخال يدوي'),
        ('vt', 'VirusTotal'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    model_version = models.ForeignKey(
        AIModelVersion, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='training_data',
        verbose_name='إصدار النموذج')

    url = models.URLField(max_length=2000, verbose_name='الرابط')
    domain = models.CharField(max_length=255, verbose_name='الدومين')
    label = models.CharField(
        max_length=20, choices=LABEL_CHOICES, verbose_name='التصنيف')

    # ── Pre-computed Features ────────────────────────────────────────────
    features = models.JSONField(default=dict, verbose_name='الخصائص المحسوبة')
    feature_schema_version = models.IntegerField(
        default=CURRENT_FEATURE_SCHEMA_VERSION,
        verbose_name='إصدار schema الخصائص')

    # Example features dict for schema v1:
    # {
    #     "url_length": 45,
    #     "domain_length": 12,
    #     "path_length": 20,
    #     "num_dots": 2,
    #     "num_hyphens": 1,
    #     "num_digits_in_domain": 3,
    #     "num_special_chars": 0,
    #     "has_ip_address": false,
    #     "has_at_symbol": false,
    #     "has_encoded_chars": false,
    #     "subdomain_count": 1,
    #     "subdomain_length": 3,
    #     "uses_https": true,
    #     "has_suspicious_tld": false,
    #     "phishing_keyword_count": 0,
    #     "compound_pattern_count": 0,
    #     "domain_age_days": 365,
    #     "has_ssl": true,
    #     "ssl_self_signed": false,
    #     "typosquatting_score": 0.0,
    #     "homoglyph_detected": false,
    #     "is_shortened": false,
    #     "entropy": 3.45,
    #     "vowel_ratio": 0.38,
    #     "digit_letter_ratio": 0.0
    # }

    source = models.CharField(
        max_length=100, choices=SOURCE_CHOICES, default='scan_history',
        verbose_name='المصدر')
    is_verified = models.BooleanField(
        default=False, verbose_name='تحقق بشري')

    created_at = models.DateTimeField(auto_now_add=True)
    export_ready_at = models.DateTimeField(
        null=True, blank=True,
        verbose_name='جاهز للتصدير',
        help_text='يُحدَّد عند جاهزية العينة لدورة التدريب القادمة')

    class Meta:
        verbose_name = 'عينة تدريب AI'
        verbose_name_plural = 'عينات تدريب AI'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['label']),
            models.Index(fields=['feature_schema_version']),
            models.Index(fields=['created_at']),
            models.Index(fields=['export_ready_at']),
            models.Index(fields=['source']),
        ]

    def __str__(self):
        verified = '✅' if self.is_verified else '⏳'
        return f"{verified} {self.url[:50]} → {self.label} (v{self.feature_schema_version})"


class AIPrediction(models.Model):
    """
    Records every AI prediction for auditing and model monitoring.

    The feedback loop:
        1. Model predicts → AIPrediction created
        2. User/admin confirms or denies → was_correct updated
        3. Training pipeline uses was_correct to improve next model version
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.OneToOneField(
        'scans.Scan', on_delete=models.CASCADE,
        related_name='ai_prediction', verbose_name='الفحص')
    model_version = models.ForeignKey(
        AIModelVersion, on_delete=models.SET_NULL, null=True,
        related_name='predictions', verbose_name='إصدار النموذج')

    url = models.URLField(max_length=2000, verbose_name='الرابط')
    features_used = models.JSONField(
        default=dict, verbose_name='الخصائص المستخدمة')
    feature_schema_version = models.IntegerField(
        default=CURRENT_FEATURE_SCHEMA_VERSION,
        verbose_name='إصدار schema الخصائص')

    prediction = models.CharField(
        max_length=20, verbose_name='التنبؤ')  # safe, phishing, malware
    confidence = models.FloatField(verbose_name='الثقة')  # 0.0 – 1.0
    risk_score = models.IntegerField(
        default=0, verbose_name='درجة الخطورة')  # 0–100

    feature_contributions = models.JSONField(
        default=dict, blank=True,
        verbose_name='مساهمات الخصائص (SHAP)')

    # Feedback loop
    was_correct = models.BooleanField(
        null=True, blank=True,
        verbose_name='هل كان التنبؤ صحيحاً')

    predicted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'تنبؤ AI'
        verbose_name_plural = 'تنبؤات AI'
        ordering = ['-predicted_at']
        indexes = [
            models.Index(fields=['prediction']),
            models.Index(fields=['was_correct']),
            models.Index(fields=['-predicted_at']),
        ]

    def __str__(self):
        correct = '✅' if self.was_correct else '❌' if self.was_correct is False else '⏳'
        return f"{correct} {self.url[:40]} → {self.prediction} ({self.confidence:.0%})"
