# apps/scans/admin.py
"""
SafeClick Admin Dashboard — Production-Grade
─────────────────────────────────────────────
Full CRUD, filtering, search, and visual badges for all scan models.
"""
from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from .models import Scan, ScanSourceResult, ScanCache, Blacklist, WhitelistEntry


# ═══════════════════════════════════════════════════════════════════════════
# SCAN ADMIN
# ═══════════════════════════════════════════════════════════════════════════

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = [
        'id_short',
        'url_short',
        'domain_display',
        'status_colored',
        'risk_badge',
        'scan_level_badge',
        'user_email',
        'timestamp_display',
        'threats_badge',
        'source_badge',
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
    
    fieldsets = (
        ('معلومات الرابط', {
            'fields': ('url', 'url_hash', 'domain_name', 'domain', 'ip_address'),
        }),
        ('المستخدم', {
            'fields': ('user', 'guest_id', 'source'),
        }),
        ('إعدادات الفحص', {
            'fields': ('scan_level',),
        }),
        ('النتائج النهائية', {
            'fields': ('final_verdict', 'risk_score', 'safe', 'result', 'score'),
            'description': 'النتيجة المجمعة من جميع محركات الفحص',
        }),
        ('تقرير الفحص', {
            'fields': ('scan_scenario', 'reason', 'details'),
            'classes': ('collapse',),
        }),
        ('التهديدات', {
            'fields': ('threats_found', 'threats_count'),
            'classes': ('collapse',),
        }),
        ('بيانات تقنية', {
            'fields': ('response_time', 'server_info'),
            'classes': ('collapse',),
        }),
        ('التواريخ', {
            'fields': ('created_at', 'updated_at', 'deleted_at'),
        }),
    )
    
    readonly_fields = ['id', 'url_hash', 'created_at', 'updated_at']
    
    actions = ['mark_safe', 'mark_malicious', 'soft_delete_selected']

    # ── Custom display methods ───────────────────────────────────────────

    def id_short(self, obj):
        return str(obj.id)[:8] + '…'
    id_short.short_description = 'المعرف'
    
    def url_short(self, obj):
        url = obj.url or ''
        return url[:55] + '…' if len(url) > 55 else url
    url_short.short_description = 'الرابط'

    def domain_display(self, obj):
        if obj.domain_name:
            return format_html(
                '<span style="font-family:monospace;color:#3b82f6;">{}</span>',
                obj.domain_name)
        return '—'
    domain_display.short_description = 'الدومين'
    
    def status_colored(self, obj):
        if obj.safe is True:
            return format_html(
                '<span style="background:#16a34a;color:#fff;padding:3px 10px;'
                'border-radius:12px;font-weight:bold;font-size:0.85em;">✅ آمن</span>')
        elif obj.safe is False:
            return format_html(
                '<span style="background:#dc2626;color:#fff;padding:3px 10px;'
                'border-radius:12px;font-weight:bold;font-size:0.85em;">🔴 خطير</span>')
        return format_html(
            '<span style="background:#f59e0b;color:#fff;padding:3px 10px;'
            'border-radius:12px;font-weight:bold;font-size:0.85em;">⚠️ مشبوه</span>')
    status_colored.short_description = 'الحالة'
    
    def risk_badge(self, obj):
        score = obj.risk_score or 0
        if score < 40:
            color, bg = '#16a34a', '#dcfce7'
        elif score < 80:
            color, bg = '#f59e0b', '#fef3c7'
        else:
            color, bg = '#dc2626', '#fee2e2'
        return format_html(
            '<div style="background:{};color:{};padding:2px 8px;border-radius:6px;'
            'text-align:center;font-weight:bold;min-width:50px;">{}</div>',
            bg, color, f'{score}%')
    risk_badge.short_description = 'الخطورة'
    
    def scan_level_badge(self, obj):
        colors = {'basic': '#6b7280', 'standard': '#3b82f6', 'deep': '#8b5cf6'}
        icons = {'basic': '⚡', 'standard': '📊', 'deep': '🔬'}
        color = colors.get(obj.scan_level, '#6b7280')
        icon = icons.get(obj.scan_level, '📋')
        return format_html(
            '<span style="background:{};color:#fff;padding:2px 6px;'
            'border-radius:8px;font-size:0.85em;">{} {}</span>',
            color, icon, obj.get_scan_level_display())
    scan_level_badge.short_description = 'المستوى'

    def user_email(self, obj):
        if obj.user:
            return obj.user.email
        if obj.guest_id:
            return format_html(
                '<span style="color:#9ca3af;font-size:0.9em;">👤 زائر</span>')
        return '—'
    user_email.short_description = 'المستخدم'
    
    def timestamp_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M')
    timestamp_display.short_description = 'التاريخ'
    
    def threats_badge(self, obj):
        count = obj.threats_count or 0
        if count > 0:
            return format_html(
                '<span style="background:#dc2626;color:#fff;padding:3px 10px;'
                'border-radius:12px;font-weight:bold;">⚠️ {}</span>', count)
        return format_html('<span style="color:#16a34a;">✅</span>')
    threats_badge.short_description = 'التهديدات'
    
    def source_badge(self, obj):
        return format_html(
            '<span style="background:#1f2937;color:#e5e7eb;padding:2px 6px;'
            'border-radius:4px;font-size:0.85em;">{}</span>', obj.source)
    source_badge.short_description = 'المصدر'

    # ── Admin Actions ────────────────────────────────────────────────────

    @admin.action(description='✅ تحديد كـ آمن')
    def mark_safe(self, request, queryset):
        count = queryset.update(safe=True, result='safe', final_verdict='safe')
        self.message_user(request, f'تم تحديد {count} فحص كآمن.')

    @admin.action(description='🔴 تحديد كـ خطير')
    def mark_malicious(self, request, queryset):
        count = queryset.update(safe=False, result='malicious', final_verdict='malicious')
        self.message_user(request, f'تم تحديد {count} فحص كخطير.')

    @admin.action(description='🗑️ حذف مؤقت (Soft Delete)')
    def soft_delete_selected(self, request, queryset):
        count = queryset.update(deleted_at=timezone.now())
        self.message_user(request, f'تم حذف {count} فحص مؤقتاً.')


# ═══════════════════════════════════════════════════════════════════════════
# SCAN SOURCE RESULT ADMIN
# ═══════════════════════════════════════════════════════════════════════════

@admin.register(ScanSourceResult)
class ScanSourceResultAdmin(admin.ModelAdmin):
    list_display = [
        'scan_url_short',
        'source_type_badge',
        'verdict_badge',
        'risk_display',
        'confidence_bar',
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

    fieldsets = (
        ('الفحص', {
            'fields': ('scan',),
        }),
        ('نتيجة المحرك', {
            'fields': ('source_type', 'verdict', 'risk_score', 'confidence', 'source_weight'),
        }),
        ('البيانات الخام', {
            'fields': ('raw_data',),
            'classes': ('collapse',),
        }),
    )

    def scan_url_short(self, obj):
        url = obj.scan.url if obj.scan else '—'
        return url[:50] + '…' if len(url) > 50 else url
    scan_url_short.short_description = 'الرابط'

    def source_type_badge(self, obj):
        colors = {
            'gsb': '#ea580c', 'vt': '#7c3aed', 'engines': '#2563eb',
            'ai': '#059669', 'blacklist': '#dc2626', 'whitelist': '#16a34a',
            'heuristic': '#6b7280',
        }
        icons = {
            'gsb': '🛡️', 'vt': '🦠', 'engines': '⚙️',
            'ai': '🧠', 'blacklist': '🚫', 'whitelist': '✅',
            'heuristic': '🔍',
        }
        color = colors.get(obj.source_type, '#6b7280')
        icon = icons.get(obj.source_type, '📋')
        return format_html(
            '<span style="background:{};color:#fff;padding:2px 8px;'
            'border-radius:8px;font-weight:bold;font-size:0.85em;">{} {}</span>',
            color, icon, obj.get_source_type_display())
    source_type_badge.short_description = 'المحرك'

    def verdict_badge(self, obj):
        colors = {
            'safe': '#16a34a', 'suspicious': '#f59e0b',
            'malicious': '#dc2626', 'error': '#6b7280', 'skipped': '#9ca3af',
        }
        color = colors.get(obj.verdict, '#6b7280')
        return format_html(
            '<span style="color:{};font-weight:bold;">{}</span>',
            color, obj.get_verdict_display())
    verdict_badge.short_description = 'الحكم'

    def risk_display(self, obj):
        score = obj.risk_score or 0
        if score <= 20:
            color = '#16a34a'
        elif score <= 50:
            color = '#f59e0b'
        else:
            color = '#dc2626'
        return format_html(
            '<span style="color:{};font-weight:bold;">{}%</span>', color, score)
    risk_display.short_description = 'الخطورة'

    def confidence_bar(self, obj):
        conf = obj.confidence or 0.0
        pct = int(conf * 100)
        color = '#16a34a' if pct >= 80 else '#f59e0b' if pct >= 50 else '#dc2626'
        return format_html(
            '<div style="background:#e5e7eb;border-radius:4px;width:80px;height:14px;">'
            '<div style="background:{};width:{}%;height:100%;border-radius:4px;"></div>'
            '</div> <small>{}%</small>', color, pct, pct)
    confidence_bar.short_description = 'الثقة'

    def weight_display(self, obj):
        return f'{obj.source_weight:.2f}'
    weight_display.short_description = 'الوزن'


# ═══════════════════════════════════════════════════════════════════════════
# SCAN CACHE ADMIN
# ═══════════════════════════════════════════════════════════════════════════

@admin.register(ScanCache)
class ScanCacheAdmin(admin.ModelAdmin):
    list_display = [
        'url_short', 'result_badge', 'risk_score',
        'scan_level_badge', 'expires_display', 'is_expired_badge',
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

    def url_short(self, obj):
        return obj.url[:55] + '…' if len(obj.url) > 55 else obj.url
    url_short.short_description = 'الرابط'

    def result_badge(self, obj):
        colors = {'safe': '#16a34a', 'suspicious': '#f59e0b', 'dangerous': '#dc2626'}
        color = colors.get(obj.result, '#6b7280')
        return format_html(
            '<span style="color:{};font-weight:bold;">{}</span>', color, obj.result)
    result_badge.short_description = 'النتيجة'

    def scan_level_badge(self, obj):
        return format_html(
            '<span style="background:#374151;color:#e5e7eb;padding:2px 6px;'
            'border-radius:4px;">{}</span>', obj.scan_level)
    scan_level_badge.short_description = 'المستوى'

    def expires_display(self, obj):
        if obj.expires_at:
            return obj.expires_at.strftime('%Y-%m-%d %H:%M')
        return '—'
    expires_display.short_description = 'ينتهي في'

    def is_expired_badge(self, obj):
        if obj.expires_at and obj.expires_at < timezone.now():
            return format_html('<span style="color:#dc2626;">❌ منتهي</span>')
        return format_html('<span style="color:#16a34a;">✅ نشط</span>')
    is_expired_badge.short_description = 'الحالة'

    @admin.action(description='🧹 حذف الكاش المنتهي')
    def clear_expired_cache(self, request, queryset):
        count = ScanCache.objects.filter(expires_at__lt=timezone.now()).delete()[0]
        self.message_user(request, f'تم حذف {count} سجل كاش منتهي.')

    @admin.action(description='⚠️ حذف كل الكاش')
    def clear_all_cache(self, request, queryset):
        count = ScanCache.objects.all().delete()[0]
        self.message_user(request, f'تم حذف {count} سجل كاش.')


# ═══════════════════════════════════════════════════════════════════════════
# BLACKLIST ADMIN
# ═══════════════════════════════════════════════════════════════════════════

@admin.register(Blacklist)
class BlacklistAdmin(admin.ModelAdmin):
    list_display = [
        'domain', 'link_short', 'threat_type_badge', 'severity_badge',
        'source', 'is_active_badge', 'added_at',
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

    def link_short(self, obj):
        link = obj.link or ''
        return link[:50] + '…' if len(link) > 50 else (link or '—')
    link_short.short_description = 'الرابط'

    def threat_type_badge(self, obj):
        colors = {
            'phishing': '#dc2626', 'malware': '#7c3aed',
            'scam': '#ea580c', 'spam': '#f59e0b', 'other': '#6b7280',
        }
        color = colors.get(obj.threat_type, '#6b7280')
        return format_html(
            '<span style="background:{};color:#fff;padding:2px 8px;'
            'border-radius:8px;font-size:0.85em;">{}</span>',
            color, obj.get_threat_type_display())
    threat_type_badge.short_description = 'نوع التهديد'

    def severity_badge(self, obj):
        colors = {'low': '#6b7280', 'medium': '#f59e0b', 'high': '#ea580c', 'critical': '#dc2626'}
        color = colors.get(obj.severity, '#6b7280')
        return format_html(
            '<span style="color:{};font-weight:bold;">{}</span>',
            color, obj.get_severity_display())
    severity_badge.short_description = 'الخطورة'

    def is_active_badge(self, obj):
        if obj.is_active:
            return format_html('<span style="color:#16a34a;">🟢 نشط</span>')
        return format_html('<span style="color:#dc2626;">🔴 معطل</span>')
    is_active_badge.short_description = 'الحالة'

    @admin.action(description='✅ تفعيل المحدد')
    def activate_selected(self, request, queryset):
        count = queryset.update(is_active=True)
        self.message_user(request, f'تم تفعيل {count} سجل.')

    @admin.action(description='❌ تعطيل المحدد')
    def deactivate_selected(self, request, queryset):
        count = queryset.update(is_active=False)
        self.message_user(request, f'تم تعطيل {count} سجل.')


# ═══════════════════════════════════════════════════════════════════════════
# WHITELIST ADMIN (NEW)
# ═══════════════════════════════════════════════════════════════════════════

@admin.register(WhitelistEntry)
class WhitelistEntryAdmin(admin.ModelAdmin):
    list_display = [
        'domain_display',
        'source_badge',
        'is_active_badge',
        'added_by_display',
        'reason_short',
        'created_at_display',
        'expiry_badge',
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
    
    fieldsets = (
        ('معلومات الدومين', {
            'fields': ('domain', 'is_active'),
        }),
        ('التصنيف', {
            'fields': ('source', 'reason', 'notes'),
        }),
        ('الإدارة', {
            'fields': ('added_by', 'expires_at'),
        }),
        ('التواريخ', {
            'fields': ('created_at', 'updated_at'),
        }),
    )
    
    actions = ['activate_selected', 'deactivate_selected', 'remove_expired']

    def domain_display(self, obj):
        return format_html(
            '<span style="font-family:monospace;font-weight:bold;color:#16a34a;'
            'font-size:1.05em;">{}</span>', obj.domain)
    domain_display.short_description = 'الدومين'

    def source_badge(self, obj):
        colors = {
            'admin': '#3b82f6', 'auto_verified': '#16a34a',
            'scan_history': '#8b5cf6', 'bloom_promoted': '#f59e0b',
        }
        color = colors.get(obj.source, '#6b7280')
        return format_html(
            '<span style="background:{};color:#fff;padding:2px 8px;'
            'border-radius:8px;font-size:0.85em;">{}</span>',
            color, obj.get_source_display())
    source_badge.short_description = 'المصدر'

    def is_active_badge(self, obj):
        if obj.is_active:
            return format_html('<span style="color:#16a34a;font-weight:bold;">🟢 نشط</span>')
        return format_html('<span style="color:#dc2626;font-weight:bold;">🔴 معطل</span>')
    is_active_badge.short_description = 'الحالة'

    def added_by_display(self, obj):
        if obj.added_by:
            return obj.added_by.email
        return format_html('<span style="color:#9ca3af;">نظام</span>')
    added_by_display.short_description = 'أضافه'

    def reason_short(self, obj):
        reason = obj.reason or ''
        return reason[:40] + '…' if len(reason) > 40 else (reason or '—')
    reason_short.short_description = 'السبب'

    def created_at_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M')
    created_at_display.short_description = 'تاريخ الإضافة'

    def expiry_badge(self, obj):
        if not obj.expires_at:
            return format_html('<span style="color:#16a34a;">♾️ دائم</span>')
        if obj.expires_at < timezone.now():
            return format_html(
                '<span style="color:#dc2626;">❌ منتهي ({})</span>',
                obj.expires_at.strftime('%Y-%m-%d'))
        return format_html(
            '<span style="color:#3b82f6;">⏰ {}</span>',
            obj.expires_at.strftime('%Y-%m-%d'))
    expiry_badge.short_description = 'الانتهاء'

    @admin.action(description='✅ تفعيل المحدد')
    def activate_selected(self, request, queryset):
        count = queryset.update(is_active=True)
        self.message_user(request, f'تم تفعيل {count} دومين.')

    @admin.action(description='❌ تعطيل المحدد')
    def deactivate_selected(self, request, queryset):
        count = queryset.update(is_active=False)
        self.message_user(request, f'تم تعطيل {count} دومين.')

    @admin.action(description='🧹 إزالة المنتهية الصلاحية')
    def remove_expired(self, request, queryset):
        count = WhitelistEntry.objects.filter(
            expires_at__lt=timezone.now()
        ).update(is_active=False)
        self.message_user(request, f'تم تعطيل {count} دومين منتهي الصلاحية.')