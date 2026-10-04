# apps/scans/admin.py
"""
SafeClick Scan & Threat Defense Admin Console — Django Unfold
─────────────────────────────────────────────────────────────
Full telemetry, multi-engine inspection, blacklist/whitelist orchestration,
and real-time verdicts.
"""
from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils import timezone
from unfold.admin import ModelAdmin, TabularInline
from unfold.decorators import display, action
from .models import Scan, ScanSourceResult, ScanCache, Blacklist, WhitelistEntry


# ═══════════════════════════════════════════════════════════════════════════
# SCAN INLINE FOR SOURCES
# ═══════════════════════════════════════════════════════════════════════════

class ScanSourceResultInline(TabularInline):
    model = ScanSourceResult
    extra = 0
    can_delete = False
    fields = ['source_type', 'verdict', 'risk_score', 'confidence', 'source_weight', 'checked_at']
    readonly_fields = ['source_type', 'verdict', 'risk_score', 'confidence', 'source_weight', 'checked_at']


# ═══════════════════════════════════════════════════════════════════════════
# SCAN ADMIN
# ═══════════════════════════════════════════════════════════════════════════

@admin.register(Scan)
class ScanAdmin(ModelAdmin):
    list_display = [
        'url_header',
        'verdict_label',
        'risk_badge',
        'user_display',
        'timestamp_display',
    ]
    
    list_filter = [
        'safe',
        'final_verdict',
        'scan_level',
        'source',
        ('created_at', admin.DateFieldListFilter),
    ]
    search_fields = ['url', 'domain_name', 'user__email', 'id', 'reason']
    list_per_page = 30
    ordering = ['-created_at']
    date_hierarchy = 'created_at'
    list_select_related = ['user', 'domain']
    list_filter_submit = True
    list_fullwidth = True
    inlines = [ScanSourceResultInline]
    
    fieldsets = (
        ('معلومات الرابط والنطاق', {
            'fields': ('url', 'url_hash', 'domain_name', 'domain', 'ip_address'),
        }),
        ('بيانات المستخدم والمصدر', {
            'fields': ('user', 'guest_id', 'source'),
        }),
        ('إعدادات الفحص', {
            'fields': ('scan_level',),
        }),
        ('النتائج والقرار الأمني الموحد', {
            'fields': ('final_verdict', 'risk_score', 'safe', 'result', 'score'),
            'description': 'القرار المجمع من كافة محركات الفحص والذكاء الاصطناعي',
        }),
        ('تقرير وسيناريو الفحص', {
            'fields': ('scan_scenario', 'reason', 'details'),
            'classes': ('collapse',),
        }),
        ('التهديدات المكتشفة', {
            'fields': ('threats_found', 'threats_count'),
            'classes': ('collapse',),
        }),
        ('البيانات التقنية والخوادم', {
            'fields': ('response_time', 'server_info'),
            'classes': ('collapse',),
        }),
        ('سجلات التوقيت', {
            'fields': ('created_at', 'updated_at', 'deleted_at'),
            'classes': ('collapse',),
        }),
    )
    
    readonly_fields = ['id', 'url_hash', 'created_at', 'updated_at']
    actions = ['mark_safe', 'mark_malicious', 'soft_delete_selected']

    @display(description='الرابط والنطاق', header=True)
    def url_header(self, obj):
        domain = obj.domain_name or (obj.domain.domain if obj.domain else 'بدون نطاق')
        url_snippet = obj.url[:60] + '…' if len(obj.url) > 60 else obj.url
        return [url_snippet, f"النطاق: {domain}"]

    @display(description='القرار الأمني', label={
        'safe': 'success',
        'malicious': 'danger',
        'suspicious': 'warning',
        'unknown': 'info',
    })
    def verdict_label(self, obj):
        if obj.final_verdict:
            return obj.final_verdict
        if obj.safe is True:
            return 'safe'
        if obj.safe is False:
            return 'malicious'
        return 'suspicious'

    @display(description='معدل الخطر', ordering='risk_score')
    def risk_badge(self, obj):
        score = obj.risk_score or 0
        if score < 40:
            return format_html('<span class="font-mono text-green-600 dark:text-green-400">{}%</span>', score)
        if score < 80:
            return format_html('<span class="font-mono text-orange-600 dark:text-orange-400 font-semibold">{}%</span>', score)
        return format_html('<span class="font-mono text-red-600 dark:text-red-400 font-bold">{}%</span>', score)

    @display(description='مستوى الفحص', label={
        'basic': 'info',
        'standard': 'primary',
        'deep': 'warning',
    })
    def scan_level_label(self, obj):
        return obj.scan_level

    @display(description='المستخدم')
    def user_display(self, obj):
        if obj.user:
            return obj.user.email
        if obj.guest_id:
            return format_html('<span class="text-base-400 font-mono text-xs">👤 زائر ({})</span>', str(obj.guest_id)[:8])
        return '—'

    @display(description='التاريخ')
    def timestamp_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M')

    @display(description='التهديدات')
    def threats_badge(self, obj):
        count = obj.threats_count or 0
        if count > 0:
            return format_html('<span class="text-red-600 dark:text-red-400 font-bold font-mono">{}</span>', count)
        return mark_safe('<span class="text-green-600 dark:text-green-400 font-mono">0</span>')

    @display(description='المصدر', label={
        'api': 'info',
        'web': 'primary',
        'mobile': 'success',
        'extension': 'warning',
    })
    def source_label(self, obj):
        return obj.source

    @action(description='تحديد كـ آمن (Safe)', icon='verified')
    def mark_safe(self, request, queryset):
        count = queryset.update(safe=True, result='safe', final_verdict='safe')
        self.message_user(request, f'تم تحديد {count} فحص كآمن.')

    @action(description='تحديد كـ خطير (Malicious)', icon='gpp_bad')
    def mark_malicious(self, request, queryset):
        count = queryset.update(safe=False, result='malicious', final_verdict='malicious')
        self.message_user(request, f'تم تحديد {count} فحص كخطير.')

    @action(description='حذف مؤقت (Soft Delete)', icon='delete')
    def soft_delete_selected(self, request, queryset):
        count = queryset.update(deleted_at=timezone.now())
        self.message_user(request, f'تم حذف {count} فحص مؤقتاً.')


# ═══════════════════════════════════════════════════════════════════════════
# SCAN SOURCE RESULT ADMIN
# ═══════════════════════════════════════════════════════════════════════════

@admin.register(ScanSourceResult)
class ScanSourceResultAdmin(ModelAdmin):
    list_display = [
        'scan_url_header',
        'source_label',
        'verdict_label',
        'risk_display',
        'confidence_display',
        'weight_display',
        'checked_at',
    ]
    list_filter = [
        'source_type',
        'verdict',
        ('checked_at', admin.DateFieldListFilter),
    ]
    search_fields = ['scan__url', 'scan__domain_name']
    list_per_page = 30
    ordering = ['-checked_at']
    date_hierarchy = 'checked_at'
    list_select_related = ['scan']
    readonly_fields = ['id', 'checked_at']
    list_filter_submit = True
    list_fullwidth = True

    fieldsets = (
        ('الفحص المرتبط', {
            'fields': ('scan',),
        }),
        ('قرار المحرك والأوزان', {
            'fields': ('source_type', 'verdict', 'risk_score', 'confidence', 'source_weight'),
        }),
        ('الاستجابة الخام (Raw Response Payload)', {
            'fields': ('raw_data',),
            'classes': ('collapse',),
        }),
    )

    @display(description='الرابط', header=True)
    def scan_url_header(self, obj):
        url = obj.scan.url if obj.scan else '—'
        return [url[:55] + '…' if len(url) > 55 else url, f"المعرف: {str(obj.scan_id)[:8] if obj.scan_id else '—'}"]

    @display(description='محرك الفحص', label={
        'gsb': 'warning',
        'vt': 'danger',
        'engines': 'primary',
        'ai': 'success',
        'blacklist': 'danger',
        'whitelist': 'success',
        'heuristic': 'info',
    })
    def source_label(self, obj):
        return obj.source_type

    @display(description='الحكم الأمني', label={
        'safe': 'success',
        'suspicious': 'warning',
        'malicious': 'danger',
        'error': 'info',
        'skipped': 'info',
    })
    def verdict_label(self, obj):
        return obj.verdict

    @display(description='معدل الخطر')
    def risk_display(self, obj):
        score = obj.risk_score or 0
        color = 'text-green-600 dark:text-green-400 font-mono' if score <= 20 else 'text-orange-600 dark:text-orange-400 font-mono' if score <= 50 else 'text-red-600 dark:text-red-400 font-mono font-bold'
        return format_html('<span class="{}">{}%</span>', color, score)

    @display(description='نسبة الثقة')
    def confidence_display(self, obj):
        conf = int((obj.confidence or 0.0) * 100)
        return format_html('<span class="font-mono text-base-300">{}%</span>', conf)

    @display(description='وزن المحرك')
    def weight_display(self, obj):
        return format_html('<span class="font-mono text-base-400">{:.2f}</span>', obj.source_weight)


# ═══════════════════════════════════════════════════════════════════════════
# SCAN CACHE ADMIN
# ═══════════════════════════════════════════════════════════════════════════

@admin.register(ScanCache)
class ScanCacheAdmin(ModelAdmin):
    list_display = [
        'url_header', 'result_label', 'risk_score',
        'scan_level', 'expires_display', 'is_active',
    ]
    list_filter = [
        'result', 'scan_level',
        ('expires_at', admin.DateFieldListFilter),
    ]
    search_fields = ['url', 'url_hash']
    list_per_page = 30
    ordering = ['-expires_at']
    readonly_fields = ['url_hash']
    actions = ['clear_expired_cache', 'clear_all_cache']
    actions_list = ['clear_expired_cache']
    list_filter_submit = True
    list_fullwidth = True

    @display(description='الرابط المحفوظ', header=True)
    def url_header(self, obj):
        url = obj.url or ''
        return [url[:55] + '…' if len(url) > 55 else url, f"Hash: {obj.url_hash[:16]}…"]

    @display(description='النتيجة', label={
        'safe': 'success',
        'suspicious': 'warning',
        'dangerous': 'danger',
    })
    def result_label(self, obj):
        return obj.result

    @display(description='صلاحية الكاش', label={
        'نشط': 'success',
        'منتهي': 'danger',
    })
    def is_active(self, obj):
        if obj.expires_at and obj.expires_at < timezone.now():
            return 'منتهي'
        return 'نشط'

    @display(description='تاريخ الانتهاء')
    def expires_display(self, obj):
        if obj.expires_at:
            return obj.expires_at.strftime('%Y-%m-%d %H:%M')
        return '—'

    @action(description='حذف الكاش المنتهي', icon='mop')
    def clear_expired_cache(self, request, queryset=None):
        count = ScanCache.objects.filter(expires_at__lt=timezone.now()).delete()[0]
        self.message_user(request, f'تم تفريغ {count} سجل كاش منتهي الصلاحية.')

    @action(description='حذف كافة سجلات الكاش', icon='delete_forever')
    def clear_all_cache(self, request, queryset=None):
        count = ScanCache.objects.all().delete()[0]
        self.message_user(request, f'تم حذف {count} سجل كاش.')


# ═══════════════════════════════════════════════════════════════════════════
# BLACKLIST ADMIN
# ═══════════════════════════════════════════════════════════════════════════

@admin.register(Blacklist)
class BlacklistAdmin(ModelAdmin):
    list_display = [
        'domain_header', 'threat_label', 'severity_label',
        'source', 'is_active', 'added_at',
    ]
    list_filter = [
        'threat_type', 'severity', 'is_active',
        ('added_at', admin.DateFieldListFilter),
    ]
    search_fields = ['domain', 'link', 'description', 'source']
    list_per_page = 30
    ordering = ['-added_at']
    date_hierarchy = 'added_at'
    actions = ['activate_selected', 'deactivate_selected']
    actions_list = ['activate_selected']
    list_filter_submit = True
    list_fullwidth = True

    @display(description='النطاق أو الرابط المحظور', header=True)
    def domain_header(self, obj):
        link_part = obj.link[:40] + '…' if obj.link and len(obj.link) > 40 else (obj.link or 'نطاق كامل')
        return [obj.domain or obj.link, link_part]

    @display(description='نوع التهديد', label={
        'phishing': 'danger',
        'malware': 'danger',
        'scam': 'warning',
        'spam': 'warning',
        'other': 'info',
    })
    def threat_label(self, obj):
        return obj.threat_type

    @display(description='الخطورة', label={
        'critical': 'danger',
        'high': 'danger',
        'medium': 'warning',
        'low': 'info',
    })
    def severity_label(self, obj):
        return obj.severity

    @action(description='✅ تفعيل المحدد', icon='check_circle')
    def activate_selected(self, request, queryset):
        count = queryset.update(is_active=True)
        self.message_user(request, f'تم تفعيل {count} سجل حظر.')

    @action(description='❌ تعطيل المحدد', icon='cancel')
    def deactivate_selected(self, request, queryset):
        count = queryset.update(is_active=False)
        self.message_user(request, f'تم تعطيل {count} سجل حظر.')


# ═══════════════════════════════════════════════════════════════════════════
# WHITELIST ADMIN
# ═══════════════════════════════════════════════════════════════════════════

@admin.register(WhitelistEntry)
class WhitelistEntryAdmin(ModelAdmin):
    list_display = [
        'domain_header',
        'source_label',
        'is_active',
        'added_by_display',
        'reason_short',
        'expiry_badge',
        'created_at_display',
    ]
    list_filter = [
        'is_active',
        'source',
        ('created_at', admin.DateFieldListFilter),
        ('expires_at', admin.DateFieldListFilter),
    ]
    search_fields = ['domain', 'reason', 'notes', 'added_by__email']
    list_per_page = 30
    ordering = ['-created_at']
    date_hierarchy = 'created_at'
    list_select_related = ['added_by']
    readonly_fields = ['id', 'created_at', 'updated_at']
    actions = ['activate_selected', 'deactivate_selected', 'remove_expired']
    actions_list = ['activate_selected']
    list_filter_submit = True
    list_fullwidth = True
    
    fieldsets = (
        ('معلومات النطاق المعتمد', {
            'fields': ('domain', 'is_active'),
        }),
        ('التصنيف والمبررات الأمنية', {
            'fields': ('source', 'reason', 'notes'),
        }),
        ('بيانات الإدارة والانتهاء', {
            'fields': ('added_by', 'expires_at'),
        }),
        ('سجلات التوقيت', {
            'fields': ('created_at', 'updated_at'),
        }),
    )

    @display(description='النطاق الموثوق', header=True)
    def domain_header(self, obj):
        reason_txt = obj.reason[:35] + '…' if obj.reason and len(obj.reason) > 35 else (obj.reason or 'اعتماد أمني')
        return [obj.domain, reason_txt]

    @display(description='المصدر', label={
        'admin': 'primary',
        'auto_verified': 'success',
        'scan_history': 'info',
        'bloom_promoted': 'warning',
    })
    def source_label(self, obj):
        return obj.source

    @display(description='أضافه')
    def added_by_display(self, obj):
        return obj.added_by.email if obj.added_by else 'النظام الآلي'

    @display(description='السبب')
    def reason_short(self, obj):
        return obj.reason[:40] + '…' if obj.reason and len(obj.reason) > 40 else (obj.reason or '—')

    @display(description='تاريخ الإضافة')
    def created_at_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M')

    @display(description='صلاحية الاعتماد', label={
        'دائم': 'success',
        'منتهي': 'danger',
        'محدد': 'info',
    })
    def expiry_badge(self, obj):
        if not obj.expires_at:
            return 'دائم'
        if obj.expires_at < timezone.now():
            return 'منتهي'
        return 'محدد'

    @action(description='تفعيل المحدد', icon='check_circle')
    def activate_selected(self, request, queryset):
        count = queryset.update(is_active=True)
        self.message_user(request, f'تم تفعيل {count} نطاق موثوق.')

    @action(description='تعطيل المحدد', icon='cancel')
    def deactivate_selected(self, request, queryset):
        count = queryset.update(is_active=False)
        self.message_user(request, f'تم تعطيل {count} نطاق.')

    @action(description='إزالة المنتهية الصلاحية', icon='cleaning_services')
    def remove_expired(self, request, queryset=None):
        count = WhitelistEntry.objects.filter(
            expires_at__lt=timezone.now()
        ).update(is_active=False)
        self.message_user(request, f'تم تعطيل {count} نطاق منتهي الصلاحية.')