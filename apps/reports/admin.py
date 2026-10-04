# apps/reports/admin.py
"""
SafeClick Incident Reporting & Community Telemetry — Django Unfold
───────────────────────────────────────────────────────────────────
Triage, investigation notes, threat confirmation, and analyst workflows.
"""
from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils import timezone
from unfold.admin import ModelAdmin, StackedInline
from unfold.decorators import display, action
from .models import Report, ReportComment


class ReportCommentInline(StackedInline):
    model = ReportComment
    extra = 1
    fields = ['user', 'content', 'is_internal']


@admin.register(Report)
class ReportAdmin(ModelAdmin):
    list_display = [
        'report_header',
        'category_display',
        'severity_label',
        'status_label',
        'reporter_info',
        'is_confirmed_badge',
        'created_at_display',
    ]
    
    list_filter = [
        'status',
        'category',
        'severity',
        'is_confirmed_threat',
        ('created_at', admin.DateFieldListFilter),
    ]
    
    search_fields = [
        'link',
        'tracking_number',
        'reporter_name',
        'description',
    ]
    
    list_per_page = 25
    ordering = ['-created_at']
    list_filter_submit = True
    list_fullwidth = True
    inlines = [ReportCommentInline]
    
    fieldsets = (
        ('معلومات البلاغ والهدف', {
            'fields': ('link', 'category', 'description', 'severity')
        }),
        ('حالة التحقيق والقرار الأمني', {
            'fields': ('status', 'is_confirmed_threat', 'investigation_notes')
        }),
        ('بيانات المبلّغ', {
            'fields': ('reporter_name', 'reporter_email', 'is_anonymous', 'user'),
            'classes': ('collapse',)
        }),
        ('سجلات المتابعة والحل', {
            'fields': ('tracking_number', 'created_at', 'reviewed_at', 'resolved_at'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ['tracking_number', 'created_at']
    
    actions = [
        'mark_as_reviewing',
        'mark_as_confirmed',
        'mark_as_resolved',
        'mark_as_rejected',
        'export_reports_csv',
    ]
    actions_list = ['mark_as_confirmed', 'mark_as_resolved']

    @display(description='البلاغ والرابط', header=True)
    def report_header(self, obj):
        link_short = obj.link[:55] + '…' if len(obj.link) > 55 else obj.link
        return [f"#{obj.tracking_number}", link_short]

    @display(description='النوع')
    def category_display(self, obj):
        return obj.get_category_display() if hasattr(obj, 'get_category_display') else obj.category

    @display(description='الخطورة', label={
        'حرج': 'danger',
        'خطير': 'danger',
        'عالي': 'warning',
        'متوسط': 'info',
        'منخفض': 'success',
    })
    def severity_label(self, obj):
        names = {5: 'حرج', 4: 'خطير', 3: 'عالي', 2: 'متوسط', 1: 'منخفض'}
        return names.get(obj.severity, str(obj.severity))

    @display(description='الحالة', label={
        'pending': 'warning',
        'reviewing': 'info',
        'confirmed': 'danger',
        'resolved': 'success',
        'rejected': 'info',
    })
    def status_label(self, obj):
        return obj.status

    @display(description='المبلّغ')
    def reporter_info(self, obj):
        if obj.is_anonymous:
            return mark_safe('<span class="text-base-400 font-mono text-xs">مجهول</span>')
        return obj.reporter_name or 'غير محدد'

    @display(description='تأكيد التهديد', label={
        'مؤكد': 'danger',
        'قيد المراجعة': 'info',
    })
    def is_confirmed_badge(self, obj):
        return 'مؤكد' if obj.is_confirmed_threat else 'قيد المراجعة'

    @display(description='التاريخ')
    def created_at_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M')

    @action(description='وضع قيد التحقيق', icon='sync')
    def mark_as_reviewing(self, request, queryset):
        updated = queryset.update(status='reviewing')
        self.message_user(request, f'تم تحويل {updated} بلاغ إلى قيد التحقيق.')

    @action(description='تأكيد كتهديد رسمي', icon='gpp_bad')
    def mark_as_confirmed(self, request, queryset):
        updated = queryset.update(
            status='confirmed',
            is_confirmed_threat=True,
            reviewed_at=timezone.now()
        )
        self.message_user(request, f'تم تأكيد {updated} بلاغ كتهديد حقيقي.')

    @action(description='اعتماد المعالجة (تم الحل)', icon='task_alt')
    def mark_as_resolved(self, request, queryset):
        updated = queryset.update(
            status='resolved',
            resolved_at=timezone.now()
        )
        self.message_user(request, f'تم إغلاق {updated} بلاغ كمعالج بنجاح.')

    @action(description='رفض البلاغ', icon='block')
    def mark_as_rejected(self, request, queryset):
        updated = queryset.update(status='rejected')
        self.message_user(request, f'تم رفض {updated} بلاغ.')

    @action(description='📥 تصدير تقارير CSV', icon='download')
    def export_reports_csv(self, request, queryset):
        import csv
        from django.http import HttpResponse
        from datetime import datetime
        
        response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
        response['Content-Disposition'] = f'attachment; filename="safeclick_reports_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['رقم التتبع', 'الرابط', 'النوع', 'الخطورة', 'الحالة', 'المبلغ', 'مؤكد', 'تاريخ البلاغ'])
        
        for r in queryset:
            writer.writerow([
                r.tracking_number,
                r.link,
                r.category,
                r.severity,
                r.status,
                'مجهول' if r.is_anonymous else r.reporter_name,
                'نعم' if r.is_confirmed_threat else 'لا',
                r.created_at.strftime('%Y-%m-%d %H:%M')
            ])
        
        return response


@admin.register(ReportComment)
class ReportCommentAdmin(ModelAdmin):
    list_display = ['comment_header', 'user_name', 'content_snippet', 'is_internal', 'created_at']
    list_filter = ['is_internal', ('created_at', admin.DateFieldListFilter)]
    search_fields = ['content', 'report__tracking_number', 'user__email']
    list_per_page = 25
    list_filter_submit = True
    list_fullwidth = True

    @display(description='البلاغ المرتبط', header=True)
    def comment_header(self, obj):
        return [f"بلاغ #{obj.report.tracking_number}", f"مستخدم: {obj.user.email if obj.user else 'غير معروف'}"]

    @display(description='المحلل')
    def user_name(self, obj):
        return obj.user.name if obj.user else 'محذوف'

    @display(description='محتوى التعليق')
    def content_snippet(self, obj):
        return obj.content[:60] + '…' if len(obj.content) > 60 else obj.content