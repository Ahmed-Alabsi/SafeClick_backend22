# apps/domains/admin.py
"""
Domain Intelligence Admin Dashboard — Production-Grade
──────────────────────────────────────────────────────
Full CRUD, filtering, search, and visual badges for domain intelligence.
"""
from django.contrib import admin
from django.utils.html import format_html
from .models import Domain, DomainIntel


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = [
        'domain_display', 'status_badge', 'age_display', 'ssl_badge',
        'dns_badge', 'scan_stats', 'threat_ratio_bar', 'last_checked',
    ]
    list_filter = [
        'is_blacklisted', 'is_whitelisted', 'has_ssl',
        'dns_resolves', 'ssl_is_expired', 'ssl_is_self_signed',
        ('created_at', admin.DateFieldListFilter),
        ('last_checked', admin.DateFieldListFilter),
    ]
    search_fields = ['domain', 'registrar', 'ssl_issuer', 'whois_country']
    list_per_page = 30
    ordering = ['-last_checked']
    date_hierarchy = 'created_at'
    readonly_fields = ['id', 'created_at', 'last_checked', 'threat_ratio']

    fieldsets = (
        ('معلومات الدومين', {
            'fields': ('domain', 'is_whitelisted', 'is_blacklisted'),
        }),
        ('بيانات التسجيل (WHOIS/RDAP)', {
            'fields': ('registrar', 'registration_date', 'expiration_date',
                       'age_days', 'whois_country'),
            'description': 'يتم تعبئتها تلقائياً من نتائج الفحص',
        }),
        ('SSL/TLS', {
            'fields': ('has_ssl', 'ssl_issuer', 'ssl_is_self_signed',
                       'ssl_is_expired', 'ssl_expiry_days', 'ssl_protocol'),
        }),
        ('DNS', {
            'fields': ('dns_resolves', 'dns_has_mx', 'dns_has_ns',
                       'dns_abnormal_config', 'dns_records'),
        }),
        ('إحصائيات الفحص', {
            'fields': ('total_scans', 'threat_detections', 'threat_ratio'),
            'description': 'يتم تحديثها تلقائياً بعد كل فحص',
        }),
        ('التواريخ', {
            'fields': ('created_at', 'last_checked'),
        }),
    )

    actions = ['mark_whitelisted', 'mark_blacklisted', 'clear_status', 'reset_stats']

    def domain_display(self, obj):
        return format_html(
            '<span style="font-family:monospace;font-weight:bold;'
            'font-size:1.05em;">{}</span>', obj.domain)
    domain_display.short_description = 'الدومين'

    def status_badge(self, obj):
        if obj.is_blacklisted:
            return format_html(
                '<span style="background:#dc2626;color:#fff;padding:3px 10px;'
                'border-radius:12px;font-weight:bold;">🔴 محظور</span>')
        if obj.is_whitelisted:
            return format_html(
                '<span style="background:#16a34a;color:#fff;padding:3px 10px;'
                'border-radius:12px;font-weight:bold;">🟢 موثوق</span>')
        return format_html(
            '<span style="background:#374151;color:#e5e7eb;padding:3px 10px;'
            'border-radius:12px;">⚪ غير مصنف</span>')
    status_badge.short_description = 'الحالة'

    def age_display(self, obj):
        if obj.age_days is None:
            return '—'
        if obj.age_days < 30:
            return format_html(
                '<span style="color:#dc2626;font-weight:bold;">{} يوم ⚠️</span>',
                obj.age_days)
        if obj.age_days < 365:
            return format_html(
                '<span style="color:#f59e0b;">{} يوم</span>', obj.age_days)
        years = obj.age_days // 365
        return format_html(
            '<span style="color:#16a34a;">{} سنة</span>', years)
    age_display.short_description = 'العمر'

    def ssl_badge(self, obj):
        if not obj.has_ssl:
            return format_html('<span style="color:#dc2626;">❌ لا يوجد</span>')
        if obj.ssl_is_expired:
            return format_html('<span style="color:#dc2626;font-weight:bold;">⚠️ منتهي</span>')
        if obj.ssl_is_self_signed:
            return format_html('<span style="color:#f59e0b;">⚠️ ذاتي</span>')
        issuer = obj.ssl_issuer or ''
        short_issuer = issuer[:15] + '…' if len(issuer) > 15 else issuer
        return format_html(
            '<span style="color:#16a34a;">✅ {}</span>',
            short_issuer or 'صالح')
    ssl_badge.short_description = 'SSL'

    def dns_badge(self, obj):
        if not obj.dns_resolves:
            return format_html('<span style="color:#dc2626;">❌ لا يستجيب</span>')
        if obj.dns_abnormal_config:
            return format_html('<span style="color:#f59e0b;">⚠️ غير طبيعي</span>')
        parts = []
        if obj.dns_has_mx:
            parts.append('MX')
        if obj.dns_has_ns:
            parts.append('NS')
        info = ', '.join(parts) if parts else 'OK'
        return format_html(
            '<span style="color:#16a34a;">✅ {}</span>', info)
    dns_badge.short_description = 'DNS'

    def scan_stats(self, obj):
        total = obj.total_scans or 0
        if total == 0:
            return '—'
        threats = obj.threat_detections or 0
        return format_html(
            '<span>{} فحص ({} تهديد)</span>', total, threats)
    scan_stats.short_description = 'الفحوصات'

    def threat_ratio_bar(self, obj):
        ratio = (obj.threat_ratio or 0) * 100
        if ratio == 0 and (obj.total_scans or 0) == 0:
            return '—'
        if ratio < 10:
            color = '#16a34a'
        elif ratio < 50:
            color = '#f59e0b'
        else:
            color = '#dc2626'
        return format_html(
            '<div style="background:#e5e7eb;border-radius:4px;width:80px;height:14px;">'
            '<div style="background:{};width:{}%;height:100%;border-radius:4px;'
            'min-width:2px;"></div></div> <small style="color:{};">{}%</small>',
            color, min(ratio, 100), color, int(ratio))
    threat_ratio_bar.short_description = 'نسبة الخطر'

    # ── Admin Actions ────────────────────────────────────────────────────

    @admin.action(description='✅ تحديد كموثوق (Whitelist)')
    def mark_whitelisted(self, request, queryset):
        count = queryset.update(is_whitelisted=True, is_blacklisted=False)
        self.message_user(request, f'تم تحديد {count} دومين كموثوق.')

    @admin.action(description='🔴 تحديد كمحظور (Blacklist)')
    def mark_blacklisted(self, request, queryset):
        count = queryset.update(is_blacklisted=True, is_whitelisted=False)
        self.message_user(request, f'تم تحديد {count} دومين كمحظور.')

    @admin.action(description='⚪ إزالة التصنيف')
    def clear_status(self, request, queryset):
        count = queryset.update(is_whitelisted=False, is_blacklisted=False)
        self.message_user(request, f'تم إزالة تصنيف {count} دومين.')

    @admin.action(description='🔄 إعادة تعيين الإحصائيات')
    def reset_stats(self, request, queryset):
        count = queryset.update(total_scans=0, threat_detections=0, threat_ratio=0.0)
        self.message_user(request, f'تم إعادة تعيين إحصائيات {count} دومين.')


@admin.register(DomainIntel)
class DomainIntelAdmin(admin.ModelAdmin):
    list_display = [
        'domain_name', 'intel_source_badge', 'threat_type_badge',
        'severity_badge', 'first_seen', 'last_seen',
    ]
    list_filter = [
        'intel_source', 'severity', 'threat_type',
        ('first_seen', admin.DateFieldListFilter),
    ]
    search_fields = ['domain__domain', 'intel_source', 'threat_type']
    list_per_page = 30
    list_select_related = ['domain']

    def domain_name(self, obj):
        return obj.domain.domain if obj.domain else '—'
    domain_name.short_description = 'الدومين'

    def intel_source_badge(self, obj):
        return format_html(
            '<span style="background:#374151;color:#e5e7eb;padding:2px 6px;'
            'border-radius:4px;">{}</span>', obj.intel_source)
    intel_source_badge.short_description = 'المصدر'

    def threat_type_badge(self, obj):
        colors = {
            'phishing': '#dc2626', 'malware': '#7c3aed',
            'scam': '#ea580c', 'spam': '#f59e0b',
        }
        color = colors.get(obj.threat_type, '#6b7280')
        return format_html(
            '<span style="color:{};font-weight:bold;">{}</span>',
            color, obj.threat_type)
    threat_type_badge.short_description = 'نوع التهديد'

    def severity_badge(self, obj):
        colors = {'low': '#6b7280', 'medium': '#f59e0b', 'high': '#ea580c', 'critical': '#dc2626'}
        color = colors.get(obj.severity, '#6b7280')
        return format_html(
            '<span style="color:{};font-weight:bold;">{}</span>',
            color, obj.severity)
    severity_badge.short_description = 'الخطورة'
