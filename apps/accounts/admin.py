# apps/accounts/admin.py
"""
SafeClick Identity & Access Admin Console — Django Unfold
──────────────────────────────────────────────────────────
Management of registered users, guest scan quotas, OTP verification
tokens, and rate-limiting IP logs.
"""
from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils import timezone
from unfold.admin import ModelAdmin
from unfold.decorators import display, action
from .models import User, GuestSession, EmailVerification, IPAttempt


@admin.register(User)
class UserAdmin(ModelAdmin):
    list_display = [
        'user_header',
        'scanned_links',
        'detected_threats',
        'accuracy_badge',
        'is_email_verified',
        'is_active',
        'is_staff',
        'created_at_display',
    ]
    list_filter = ['is_active', 'is_staff', 'is_email_verified', 'created_at']
    search_fields = ['email', 'name', 'id']
    ordering = ['-created_at']
    list_per_page = 25
    list_filter_submit = True
    list_fullwidth = True
    
    fieldsets = (
        ('معلومات الحساب والاعتماد', {'fields': ('email', 'password')}),
        ('الملف الشخصي', {'fields': ('name', 'profile_image')}),
        ('إحصائيات الفحص والأمان', {
            'fields': ('scanned_links', 'detected_threats', 'accuracy_rate'),
            'description': 'تُحدث هذه البيانات آلياً بعد كل فحص للروابط',
        }),
        ('الحالة والصلاحيات', {'fields': ('is_active', 'is_staff', 'is_superuser', 'is_email_verified')}),
        ('سجلات التوقيت', {'fields': ('last_login', 'created_at')}),
    )
    
    readonly_fields = ['created_at', 'last_login', 'scanned_links', 'detected_threats', 'accuracy_rate']

    @display(description='المستخدم', header=True)
    def user_header(self, obj):
        return [obj.name, obj.email]

    @display(description='معدل الدقة')
    def accuracy_badge(self, obj):
        color = 'text-green-600 dark:text-green-400 font-bold' if obj.accuracy_rate >= 80 else 'text-orange-600 dark:text-orange-400' if obj.accuracy_rate >= 50 else 'text-red-600 dark:text-red-400'
        return format_html('<span class="font-mono {}">{}%</span>', color, obj.accuracy_rate)

    @display(description='تاريخ الانضمام')
    def created_at_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d')


@admin.register(GuestSession)
class GuestSessionAdmin(ModelAdmin):
    list_display = [
        'guest_header',
        'ip_address',
        'scans_progress',
        'is_active',
        'status_badge',
        'created_at_display',
        'expires_at_display',
    ]
    list_filter = ['is_active', ('created_at', admin.DateFieldListFilter), ('expires_at', admin.DateFieldListFilter)]
    search_fields = ['id', 'ip_address']
    list_per_page = 30
    ordering = ['-created_at']
    list_filter_submit = True
    list_fullwidth = True

    @display(description='جلسة الزائر', header=True)
    def guest_header(self, obj):
        return [f"Guest-{str(obj.id)[:8]}", f"IP: {obj.ip_address or 'غير معروف'}"]

    @display(description='استهلاك الحصة (Quota)')
    def scans_progress(self, obj):
        color = 'text-green-600 dark:text-green-400' if obj.scans_used < 2 else 'text-orange-600 dark:text-orange-400' if obj.scans_used == 2 else 'text-red-600 dark:text-red-400 font-bold'
        return format_html('<span class="font-mono {}">{}/3 فحوصات</span>', color, obj.scans_used)

    @display(description='صلاحية الجلسة', label={
        'صالحة': 'success',
        'منتهية': 'danger',
    })
    def status_badge(self, obj):
        return 'صالحة' if obj.is_valid() else 'منتهية'

    @display(description='تاريخ الإنشاء')
    def created_at_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M')

    @display(description='تاريخ الانتهاء')
    def expires_at_display(self, obj):
        return obj.expires_at.strftime('%Y-%m-%d %H:%M')


@admin.register(EmailVerification)
class EmailVerificationAdmin(ModelAdmin):
    list_display = [
        'email_header',
        'purpose_label',
        'attempts_display',
        'lockout_status',
        'is_expired',
        'created_at_display',
    ]
    list_filter = ['purpose', ('created_at', admin.DateFieldListFilter)]
    search_fields = ['email', 'name']
    list_per_page = 30
    ordering = ['-created_at']
    list_filter_submit = True
    list_fullwidth = True

    @display(description='البريد الإلكتروني', header=True)
    def email_header(self, obj):
        return [obj.email, f"الاسم: {obj.name or '—'}"]

    @display(description='الغرض', label={
        'register': 'primary',
        'reset': 'warning',
    })
    def purpose_label(self, obj):
        return obj.purpose

    @display(description='محاولات OTP')
    def attempts_display(self, obj):
        color = 'text-green-600 dark:text-green-400 font-mono' if obj.otp_attempts < 3 else 'text-red-600 dark:text-red-400 font-mono font-bold'
        return format_html('<span class="{}">{}/5</span>', color, obj.otp_attempts)

    @display(description='الحظر المؤقت (Lockout)', label={
        'مقفل': 'danger',
        'متاح': 'success',
    })
    def lockout_status(self, obj):
        if obj.lockout_until and obj.lockout_until > timezone.now():
            return 'مقفل'
        return 'متاح'

    @display(description='الصلاحية', label={
        'نشط': 'success',
        'منتهي': 'danger',
    })
    def is_expired(self, obj):
        if obj.expires_at < timezone.now():
            return 'منتهي'
        return 'نشط'

    @display(description='تاريخ الطلب')
    def created_at_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M')


@admin.register(IPAttempt)
class IPAttemptAdmin(ModelAdmin):
    list_display = [
        'ip_header',
        'attempts_badge',
        'status_label',
        'last_attempt_at',
    ]
    search_fields = ['ip_address']
    ordering = ['-last_attempt_at']
    list_per_page = 40
    list_filter_submit = True
    list_fullwidth = True

    @display(description='عنوان IP', header=True)
    def ip_header(self, obj):
        return [obj.ip_address, f"آخر محاولة: {obj.last_attempt_at.strftime('%Y-%m-%d %H:%M')}"]

    @display(description='عدد المحاولات')
    def attempts_badge(self, obj):
        color = 'text-green-600 dark:text-green-400 font-mono' if obj.count < 3 else 'text-orange-600 dark:text-orange-400 font-mono' if obj.count < 5 else 'text-red-600 dark:text-red-400 font-mono font-bold'
        return format_html('<span class="{}">{} محاولة</span>', color, obj.count)

    @display(description='الحالة الأمنية', label={
        'آمن': 'success',
        'مريب': 'warning',
        'محظور': 'danger',
    })
    def status_label(self, obj):
        if obj.count >= 5:
            return 'محظور'
        if obj.count >= 3:
            return 'مريب'
        return 'آمن'