# apps/ai/admin.py
from django.contrib import admin
from django.utils.html import format_html
from .models import AIModelVersion, AITrainingDataset, AIPrediction


@admin.register(AIModelVersion)
class AIModelVersionAdmin(admin.ModelAdmin):
    list_display = ['version', 'algorithm', 'status_badge', 'metrics_display',
                    'training_samples', 'trained_at']
    list_filter = ['status', 'algorithm']
    search_fields = ['version', 'model_name']
    readonly_fields = ['id', 'created_at']

    def status_badge(self, obj):
        colors = {
            'training': '#f59e0b',
            'validating': '#3b82f6',
            'ready': '#10b981',
            'deployed': '#16a34a',
            'archived': '#6b7280',
        }
        color = colors.get(obj.status, '#6b7280')
        return format_html(
            '<span style="background:{};color:#fff;padding:3px 8px;'
            'border-radius:10px;font-weight:bold;">{}</span>',
            color, obj.get_status_display())
    status_badge.short_description = 'الحالة'

    def metrics_display(self, obj):
        f1 = f"{obj.f1_score:.2f}" if obj.f1_score else "N/A"
        acc = f"{obj.accuracy:.2f}" if obj.accuracy else "N/A"
        auc = f"{obj.auc_roc:.2f}" if obj.auc_roc else "N/A"
        return format_html('F1={} | Acc={} | AUC={}', f1, acc, auc)
    metrics_display.short_description = 'الأداء'


@admin.register(AITrainingDataset)
class AITrainingDatasetAdmin(admin.ModelAdmin):
    list_display = ['url_short', 'label', 'source', 'is_verified',
                    'feature_schema_version', 'created_at']
    list_filter = ['label', 'source', 'is_verified', 'feature_schema_version']
    search_fields = ['url', 'domain']
    list_per_page = 50

    def url_short(self, obj):
        return obj.url[:60] + '...' if len(obj.url) > 60 else obj.url
    url_short.short_description = 'الرابط'


@admin.register(AIPrediction)
class AIPredictionAdmin(admin.ModelAdmin):
    list_display = ['url_short', 'prediction', 'confidence_display',
                    'correctness_badge', 'model_version', 'predicted_at']
    list_filter = ['prediction', 'was_correct']
    search_fields = ['url']
    list_per_page = 50

    def url_short(self, obj):
        return obj.url[:60] + '...' if len(obj.url) > 60 else obj.url
    url_short.short_description = 'الرابط'

    def confidence_display(self, obj):
        color = 'green' if obj.confidence > 0.8 else 'orange' if obj.confidence > 0.5 else 'red'
        return format_html(
            '<span style="color:{};">{}%</span>', color, int((obj.confidence or 0) * 100))
    confidence_display.short_description = 'الثقة'

    def correctness_badge(self, obj):
        if obj.was_correct is True:
            return format_html('<span style="color:green;">✅ صحيح</span>')
        if obj.was_correct is False:
            return format_html('<span style="color:red;">❌ خاطئ</span>')
        return format_html('<span style="color:gray;">⏳ غير محدد</span>')
    correctness_badge.short_description = 'النتيجة'
