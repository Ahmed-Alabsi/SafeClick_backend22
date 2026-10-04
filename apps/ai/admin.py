# apps/ai/admin.py
"""
SafeClick AI & Machine Learning Model Console — Django Unfold
──────────────────────────────────────────────────────────────
Tracking model versions, training datasets, predictions accuracy,
and feature weights.
"""
from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from unfold.admin import ModelAdmin
from unfold.decorators import display
from .models import AIModelVersion, AITrainingDataset, AIPrediction


@admin.register(AIModelVersion)
class AIModelVersionAdmin(ModelAdmin):
    list_display = [
        'version_header',
        'algorithm',
        'status_label',
        'metrics_display',
        'training_samples',
        'trained_at',
    ]
    list_filter = ['status', 'algorithm', ('trained_at', admin.DateFieldListFilter)]
    search_fields = ['version', 'model_name']
    readonly_fields = ['id', 'created_at']
    list_filter_submit = True
    list_fullwidth = True

    @display(description='الإصدار والنموذج', header=True)
    def version_header(self, obj):
        return [f"v{obj.version}", obj.model_name or "SafeClick Classifier"]

    @display(description='الحالة', label={
        'training': 'warning',
        'validating': 'info',
        'ready': 'success',
        'deployed': 'primary',
        'archived': 'info',
    })
    def status_label(self, obj):
        return obj.status

    @display(description='مقاييس الأداء')
    def metrics_display(self, obj):
        f1 = f"{obj.f1_score:.2f}" if obj.f1_score else "N/A"
        acc = f"{obj.accuracy:.2f}" if obj.accuracy else "N/A"
        auc = f"{obj.auc_roc:.2f}" if obj.auc_roc else "N/A"
        return format_html('<span class="font-mono text-xs text-base-300">F1:{} | Acc:{} | AUC:{}</span>', f1, acc, auc)


@admin.register(AITrainingDataset)
class AITrainingDatasetAdmin(ModelAdmin):
    list_display = [
        'url_header',
        'label_badge',
        'source',
        'is_verified',
        'feature_schema_version',
        'created_at_display',
    ]
    list_filter = ['label', 'source', 'is_verified', 'feature_schema_version']
    search_fields = ['url', 'domain']
    list_per_page = 50
    list_filter_submit = True
    list_fullwidth = True

    @display(description='الرابط والنطاق', header=True)
    def url_header(self, obj):
        url_short = obj.url[:55] + '…' if len(obj.url) > 55 else obj.url
        return [url_short, f"نطاق: {obj.domain or '—'}"]

    @display(description='التصنيف التدريبي', label={
        'phishing': 'danger',
        'malware': 'danger',
        'safe': 'success',
        'benign': 'success',
        'suspicious': 'warning',
    })
    def label_badge(self, obj):
        return obj.label

    @display(description='تاريخ الإضافة')
    def created_at_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d')


@admin.register(AIPrediction)
class AIPredictionAdmin(ModelAdmin):
    list_display = [
        'url_header',
        'prediction_label',
        'confidence_display',
        'correctness_badge',
        'model_version',
        'predicted_at_display',
    ]
    list_filter = ['prediction', 'was_correct', ('predicted_at', admin.DateFieldListFilter)]
    search_fields = ['url']
    list_per_page = 50
    list_filter_submit = True
    list_fullwidth = True

    @display(description='الرابط المستهدف', header=True)
    def url_header(self, obj):
        url_short = obj.url[:55] + '…' if len(obj.url) > 55 else obj.url
        return [url_short, f"نموذج: {obj.model_version}"]

    @display(description='التنبؤ', label={
        'malicious': 'danger',
        'phishing': 'danger',
        'safe': 'success',
        'suspicious': 'warning',
    })
    def prediction_label(self, obj):
        return obj.prediction

    @display(description='درجة الثقة')
    def confidence_display(self, obj):
        conf = int((obj.confidence or 0) * 100)
        color = 'text-green-600 dark:text-green-400 font-bold' if conf > 80 else 'text-orange-600 dark:text-orange-400' if conf > 50 else 'text-red-600 dark:text-red-400'
        return format_html('<span class="font-mono {}">{}%</span>', color, conf)

    @display(description='صحة التنبؤ', label={
        'دقيق': 'success',
        'غير دقيق': 'danger',
        'قيد التحقق': 'info',
    })
    def correctness_badge(self, obj):
        if obj.was_correct is True:
            return 'دقيق'
        if obj.was_correct is False:
            return 'غير دقيق'
        return 'قيد التحقق'

    @display(description='التوقيت')
    def predicted_at_display(self, obj):
        return obj.predicted_at.strftime('%Y-%m-%d %H:%M')
