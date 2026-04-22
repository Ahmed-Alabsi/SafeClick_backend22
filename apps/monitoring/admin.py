# apps/monitoring/admin.py
from django.contrib import admin
from django.utils.html import format_html
from .models import EngineHealthLog


@admin.register(EngineHealthLog)
class EngineHealthLogAdmin(admin.ModelAdmin):
    list_display = ['engine_display', 'status_badge', 'latency_display',
                    'error_short', 'checked_at']
    list_filter = ['engine_name', 'status']
    search_fields = ['engine_name', 'error_message', 'scan_url']
    list_per_page = 50
    ordering = ['-checked_at']

    def engine_display(self, obj):
        return obj.get_engine_name_display()
    engine_display.short_description = 'المحرك'

    def status_badge(self, obj):
        colors = {
            'ok': '#16a34a',
            'degraded': '#f59e0b',
            'error': '#dc2626',
            'timeout': '#dc2626',
            'skipped': '#6b7280',
        }
        icons = {
            'ok': '✅', 'degraded': '⚠️', 'error': '❌',
            'timeout': '⏱️', 'skipped': '⏭️',
        }
        color = colors.get(obj.status, '#6b7280')
        icon = icons.get(obj.status, '❓')
        return format_html(
            '<span style="background:{};color:#fff;padding:3px 8px;'
            'border-radius:10px;">{} {}</span>',
            color, icon, obj.get_status_display())
    status_badge.short_description = 'الحالة'

    def latency_display(self, obj):
        if obj.latency_ms < 100:
            color = 'green'
        elif obj.latency_ms < 1000:
            color = 'orange'
        else:
            color = 'red'
        return format_html(
            '<span style="color:{};">{}ms</span>',
            color, int(obj.latency_ms) if obj.latency_ms is not None else 0)
    latency_display.short_description = 'الاستجابة'

    def error_short(self, obj):
        if not obj.error_message:
            return '—'
        return obj.error_message[:80] + '...' if len(obj.error_message) > 80 else obj.error_message
    error_short.short_description = 'الخطأ'
