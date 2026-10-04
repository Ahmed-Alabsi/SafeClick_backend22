# apps/monitoring/admin.py
"""
SafeClick Engine Health Monitoring Console — Django Unfold
───────────────────────────────────────────────────────────
Real-time inspection of detection latency, failure rates, and upstream API status.
"""
from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from unfold.admin import ModelAdmin
from unfold.decorators import display
from .models import EngineHealthLog


@admin.register(EngineHealthLog)
class EngineHealthLogAdmin(ModelAdmin):
    list_display = [
        'engine_header',
        'status_label',
        'latency_display',
        'error_short',
        'checked_at_display',
    ]
    list_filter = ['engine_name', 'status', ('checked_at', admin.DateFieldListFilter)]
    search_fields = ['engine_name', 'error_message', 'scan_url']
    list_per_page = 50
    ordering = ['-checked_at']
    list_filter_submit = True
    list_fullwidth = True

    @display(description='المحرك الأمني', header=True)
    def engine_header(self, obj):
        latency = f"{int(obj.latency_ms)}ms" if obj.latency_ms is not None else "N/A"
        return [obj.get_engine_name_display(), f"زمن الاستجابة: {latency}"]

    @display(description='الحالة التشغيلية', label={
        'ok': 'success',
        'degraded': 'warning',
        'error': 'danger',
        'timeout': 'danger',
        'skipped': 'info',
    })
    def status_label(self, obj):
        return obj.status

    @display(description='زمن الاستجابة')
    def latency_display(self, obj):
        if obj.latency_ms is None:
            return '—'
        ms = int(obj.latency_ms)
        color = 'text-green-600 dark:text-green-400' if ms < 200 else 'text-orange-600 dark:text-orange-400' if ms < 1000 else 'text-red-600 dark:text-red-400 font-bold'
        return format_html('<span class="font-mono {}">{}ms</span>', color, ms)

    @display(description='رسالة الخطأ')
    def error_short(self, obj):
        if not obj.error_message:
            return mark_safe('<span class="text-base-400">—</span>')
        return format_html('<span class="text-red-600 dark:text-red-400 font-mono text-xs">{}</span>', obj.error_message[:75])

    @display(description='تاريخ الفحص')
    def checked_at_display(self, obj):
        return obj.checked_at.strftime('%Y-%m-%d %H:%M:%S')
