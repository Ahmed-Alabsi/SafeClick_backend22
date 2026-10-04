# apps/domains/admin.py
"""
SafeClick Domain & Brand Intelligence Admin Console — Django Unfold
───────────────────────────────────────────────────────────────────
High-performance brand protection, domain telemetry, verified catalogs,
and instant cache synchronization.
"""
from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from unfold.admin import ModelAdmin, TabularInline
from unfold.decorators import display, action
from .models import Domain, DomainIntel, Brand, BrandDomain, BrandKeyword


# ══════════════════════════════════════════════════════════════════════════════
# Domain Admin
# ══════════════════════════════════════════════════════════════════════════════

@admin.register(Domain)
class DomainAdmin(ModelAdmin):
    list_display = [
        'domain_header', 'status_label', 'age_display', 'scan_stats', 'last_checked',
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
    list_filter_submit = True
    list_fullwidth = True

    fieldsets = (
        ('معلومات النطاق الأساسية', {
            'fields': ('domain', 'is_whitelisted', 'is_blacklisted'),
        }),
        ('بيانات التسجيل (WHOIS / RDAP)', {
            'fields': ('registrar', 'registration_date', 'expiration_date',
                       'age_days', 'whois_country'),
            'description': 'يتم استخراجها وتحديثها تلقائياً أثناء دورة الفحص الاستباقي',
        }),
        ('شهادة الأمان المشفرة (SSL / TLS)', {
            'fields': ('has_ssl', 'ssl_issuer', 'ssl_is_self_signed',
                       'ssl_is_expired', 'ssl_expiry_days', 'ssl_protocol'),
        }),
        ('إعدادات خوادم الأسماء (DNS Telemetry)', {
            'fields': ('dns_resolves', 'dns_has_mx', 'dns_has_ns',
                       'dns_abnormal_config', 'dns_records'),
        }),
        ('إحصائيات الفحص ومعدل الخطر', {
            'fields': ('total_scans', 'threat_detections', 'threat_ratio'),
            'description': 'مؤشرات تراكمية للتهديدات المرصودة على هذا النطاق',
        }),
        ('سجلات التوقيت', {
            'fields': ('created_at', 'last_checked'),
            'classes': ('collapse',),
        }),
    )

    actions = ['mark_whitelisted', 'mark_blacklisted', 'clear_status', 'reset_stats']

    @display(description='النطاق', header=True)
    def domain_header(self, obj):
        sub = f"سجل بواسطة: {obj.registrar}" if obj.registrar else "غير مسجل"
        return [obj.domain, sub]

    @display(description='التصنيف الأمني', label={
        'محظور': 'danger',
        'موثوق': 'success',
        'غير مصنف': 'info',
    })
    def status_label(self, obj):
        if obj.is_blacklisted:
            return 'محظور'
        if obj.is_whitelisted:
            return 'موثوق'
        return 'غير مصنف'

    @display(description='عمر النطاق')
    def age_display(self, obj):
        if obj.age_days is None:
            return '—'
        if obj.age_days < 30:
            return format_html('<span class="text-red-600 dark:text-red-400 font-semibold font-mono">{} يوم (حديث)</span>', obj.age_days)
        if obj.age_days < 365:
            return format_html('<span class="text-orange-600 dark:text-orange-400 font-mono">{} يوم</span>', obj.age_days)
        years = obj.age_days // 365
        return format_html('<span class="text-green-600 dark:text-green-400 font-mono">{} سنة</span>', years)

    @display(description='حالة SSL', label={
        'صالح': 'success',
        'مفقود': 'danger',
        'منتهي': 'danger',
        'ذاتي': 'warning',
    })
    def ssl_status(self, obj):
        if not obj.has_ssl:
            return 'مفقود'
        if obj.ssl_is_expired:
            return 'منتهي'
        if obj.ssl_is_self_signed:
            return 'ذاتي'
        return 'صالح'

    @display(description='خوادم DNS', label={
        'متصل': 'success',
        'لا يستجيب': 'danger',
        'شاذ': 'warning',
    })
    def dns_status(self, obj):
        if not obj.dns_resolves:
            return 'لا يستجيب'
        if obj.dns_abnormal_config:
            return 'شاذ'
        return 'متصل'

    @display(description='الفحوصات')
    def scan_stats(self, obj):
        total = obj.total_scans or 0
        if total == 0:
            return '—'
        threats = obj.threat_detections or 0
        return format_html('<span class="font-mono text-xs">{} فحص ({} تهديد)</span>', total, threats)

    @display(description='معدل الخطر')
    def threat_ratio_display(self, obj):
        ratio = (obj.threat_ratio or 0) * 100
        if ratio == 0 and (obj.total_scans or 0) == 0:
            return '—'
        color = 'text-green-600 dark:text-green-400' if ratio < 10 else 'text-orange-600 dark:text-orange-400' if ratio < 50 else 'text-red-600 dark:text-red-400 font-bold'
        return format_html('<span class="font-mono {}">{}%</span>', color, int(ratio))

    @action(description='تحديد كموثوق (Whitelist)', icon='verified')
    def mark_whitelisted(self, request, queryset):
        count = queryset.update(is_whitelisted=True, is_blacklisted=False)
        self.message_user(request, f'تم تحديد {count} نطاق كموثوق.')

    @action(description='تحديد كمحظور (Blacklist)', icon='block')
    def mark_blacklisted(self, request, queryset):
        count = queryset.update(is_blacklisted=True, is_whitelisted=False)
        self.message_user(request, f'تم تحديد {count} نطاق كمحظور.')

    @action(description='إزالة التصنيف', icon='restart_alt')
    def clear_status(self, request, queryset):
        count = queryset.update(is_whitelisted=False, is_blacklisted=False)
        self.message_user(request, f'تم إزالة تصنيف {count} نطاق.')

    @action(description='🔄 إعادة تعيين الإحصائيات', icon='refresh')
    def reset_stats(self, request, queryset):
        count = queryset.update(total_scans=0, threat_detections=0, threat_ratio=0.0)
        self.message_user(request, f'تم إعادة تعيين إحصائيات {count} نطاق.')


# ══════════════════════════════════════════════════════════════════════════════
# Domain Intel Admin
# ══════════════════════════════════════════════════════════════════════════════

@admin.register(DomainIntel)
class DomainIntelAdmin(ModelAdmin):
    list_display = [
        'domain_name', 'intel_source', 'threat_label',
        'severity_label', 'first_seen', 'last_seen',
    ]
    list_filter = [
        'intel_source', 'severity', 'threat_type',
        ('first_seen', admin.DateFieldListFilter),
    ]
    search_fields = ['domain__domain', 'intel_source', 'threat_type']
    list_per_page = 30
    list_select_related = ['domain']
    list_filter_submit = True
    list_fullwidth = True

    @display(description='النطاق', header=True)
    def domain_name(self, obj):
        name = obj.domain.domain if obj.domain else '—'
        return [name, f"المصدر: {obj.intel_source}"]

    @display(description='نوع التهديد', label={
        'phishing': 'danger',
        'malware': 'danger',
        'scam': 'warning',
        'spam': 'info',
    })
    def threat_label(self, obj):
        return obj.threat_type

    @display(description='مستوى الخطورة', label={
        'critical': 'danger',
        'high': 'danger',
        'medium': 'warning',
        'low': 'info',
    })
    def severity_label(self, obj):
        return obj.severity


# ══════════════════════════════════════════════════════════════════════════════
# Brand Intelligence Catalog Admin
# ══════════════════════════════════════════════════════════════════════════════

class BrandDomainInline(TabularInline):
    model = BrandDomain
    extra = 1
    fields = ['domain', 'is_primary', 'status', 'verification_source', 'is_active']


class BrandKeywordInline(TabularInline):
    model = BrandKeyword
    extra = 1
    fields = ['keyword', 'match_strategy', 'weight', 'is_active']


@admin.register(Brand)
class BrandAdmin(ModelAdmin):
    list_display = [
        'brand_header', 'slug', 'sector_label', 'country', 'risk_label',
        'verified_domains_count', 'keywords_count', 'is_active',
    ]
    list_filter = ['sector', 'country', 'risk_weight', 'is_active']
    search_fields = ['name', 'name_ar', 'slug', 'domains__domain', 'keywords__keyword']
    list_per_page = 30
    inlines = [BrandDomainInline, BrandKeywordInline]
    actions = ['activate_brands', 'deactivate_brands', 'bump_catalog_cache']
    actions_list = ['bump_catalog_cache']
    list_filter_submit = True
    list_fullwidth = True

    @display(description='العلامة التجارية / الجهة', header=True)
    def brand_header(self, obj):
        return [obj.name, obj.name_ar or '']

    @display(description='القطاع', label={
        'banking': 'success',
        'fintech': 'info',
        'government': 'primary',
        'telecom': 'warning',
        'ecommerce': 'warning',
        'tech': 'info',
    })
    def sector_label(self, obj):
        return obj.sector

    @display(description='حساسية التهديد', label={
        'CRITICAL': 'danger',
        'HIGH': 'warning',
        'MEDIUM': 'info',
    })
    def risk_label(self, obj):
        return obj.risk_weight

    @display(description='النطاقات المعتمدة')
    def verified_domains_count(self, obj):
        count = obj.domains.filter(status='VERIFIED', is_active=True).count()
        return format_html('<span class="text-green-600 dark:text-green-400 font-semibold font-mono">{} نطاق</span>', count)

    @display(description='الكلمات المفتاحية')
    def keywords_count(self, obj):
        count = obj.keywords.filter(is_active=True).count()
        return format_html('<span class="font-mono text-base-400">{} كلمة</span>', count)

    @action(description="تفعيل العلامات المحددة", icon='check_circle')
    def activate_brands(self, request, queryset):
        queryset.update(is_active=True)
        from .services.brand_service import BrandService
        BrandService.bump_version()
        self.message_user(request, "تم تفعيل العلامات المحددة وتحديث الكاش.")

    @action(description="تعطيل العلامات المحددة", icon='cancel')
    def deactivate_brands(self, request, queryset):
        queryset.update(is_active=False)
        from .services.brand_service import BrandService
        BrandService.bump_version()
        self.message_user(request, "تم تعطيل العلامات المحددة وتحديث الكاش.")

    @action(description="⚡ تحديث كاش محركات الفحص فورياً (Sync Catalog Cache)", icon='sync')
    def bump_catalog_cache(self, request, queryset=None):
        from .services.brand_service import BrandService
        new_v = BrandService.bump_version()
        self.message_user(request, f"تم تحديث نسخة الكتالوج بنجاح إلى v{new_v}. جميع محركات الفحص تم تحديثها فورياً.")


@admin.register(BrandDomain)
class BrandDomainAdmin(ModelAdmin):
    list_display = ['domain_header', 'brand', 'status_label', 'is_primary', 'verification_source', 'is_active']
    list_filter = ['status', 'is_primary', 'is_active', 'brand__sector']
    search_fields = ['domain', 'brand__name', 'brand__slug']
    list_per_page = 30
    actions = ['mark_verified', 'mark_pending', 'mark_deprecated', 'activate_domains', 'deactivate_domains']
    list_filter_submit = True
    list_fullwidth = True

    @display(description='النطاق الرسمي', header=True)
    def domain_header(self, obj):
        primary_text = "⭐ نطاق أساسي" if obj.is_primary else "نطاق معتمد"
        return [obj.domain, primary_text]

    @display(description='حالة الاعتماد', label={
        'VERIFIED': 'success',
        'PENDING': 'warning',
        'DEPRECATED': 'danger',
    })
    def status_label(self, obj):
        return obj.status

    @action(description="✅ اعتماد رسمي (VERIFIED)", icon='verified')
    def mark_verified(self, request, queryset):
        from django.utils import timezone
        count = queryset.update(status='VERIFIED', verified_at=timezone.now(), is_active=True)
        from .services.brand_service import BrandService
        BrandService.bump_version()
        self.message_user(request, f"تم اعتماد {count} نطاق رسمياً وتحديث كاش المحركات.")

    @action(description="⚠️ تعليق النطاقات (PENDING)", icon='pending')
    def mark_pending(self, request, queryset):
        count = queryset.update(status='PENDING')
        from .services.brand_service import BrandService
        BrandService.bump_version()
        self.message_user(request, f"تم تحويل {count} نطاق إلى قيد التحقق.")

    @action(description="🔴 إيقاف الاعتماد (DEPRECATED)", icon='block')
    def mark_deprecated(self, request, queryset):
        count = queryset.update(status='DEPRECATED')
        from .services.brand_service import BrandService
        BrandService.bump_version()
        self.message_user(request, f"تم إيقاف {count} نطاق وإزالته من القائمة البيضاء السريعة.")

    @action(description="تفعيل النطاقات المحددة", icon='check')
    def activate_domains(self, request, queryset):
        count = queryset.update(is_active=True)
        from .services.brand_service import BrandService
        BrandService.bump_version()
        self.message_user(request, f"تم تفعيل {count} نطاق.")

    @action(description="تعطيل النطاقات المحددة", icon='close')
    def deactivate_domains(self, request, queryset):
        count = queryset.update(is_active=False)
        from .services.brand_service import BrandService
        BrandService.bump_version()
        self.message_user(request, f"تم تعطيل {count} نطاق.")


@admin.register(BrandKeyword)
class BrandKeywordAdmin(ModelAdmin):
    list_display = ['keyword_header', 'brand', 'strategy_label', 'weight_display', 'is_active']
    list_filter = ['match_strategy', 'is_active', 'brand__sector']
    search_fields = ['keyword', 'brand__name', 'brand__slug']
    list_per_page = 40
    list_filter_submit = True
    list_fullwidth = True

    @display(description='الكلمة المفتاحية', header=True)
    def keyword_header(self, obj):
        return [obj.keyword, f"العلامة: {obj.brand.name}"]

    @display(description='استراتيجية المطابقة', label={
        'TOKEN_BOUNDARY': 'primary',
        'TYPO_SIMILARITY': 'info',
        'CONTAINS': 'warning',
        'EXACT': 'success',
    })
    def strategy_label(self, obj):
        return obj.match_strategy

    @display(description='وزن التأثير')
    def weight_display(self, obj):
        return format_html('<span class="font-mono font-bold text-orange-600 dark:text-orange-400">{}</span>', obj.weight)
