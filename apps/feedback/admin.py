# apps/feedback/admin.py
"""
SafeClick User Feedback & Ratings Console — Django Unfold
"""
from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from unfold.admin import ModelAdmin
from unfold.decorators import display
from .models import AppRating


@admin.register(AppRating)
class AppRatingAdmin(ModelAdmin):
    list_display = ('user_header', 'stars_display', 'comment_snippet', 'created_at', 'updated_at')
    list_filter = ('rating', ('created_at', admin.DateFieldListFilter))
    search_fields = ('user__email', 'user__name', 'comment')
    readonly_fields = ('created_at', 'updated_at')
    list_filter_submit = True
    list_fullwidth = True

    @display(description='المستخدم', header=True)
    def user_header(self, obj):
        return [obj.user.name or obj.user.email, obj.user.email]

    @display(description='التقييم')
    def stars_display(self, obj):
        stars = "★" * obj.rating + "☆" * (5 - obj.rating)
        color = 'text-orange-500' if obj.rating >= 3 else 'text-red-500'
        return format_html('<span class="text-base font-mono {}">{} ({}/5)</span>', color, stars, obj.rating)

    @display(description='الملاحظات والتعليق')
    def comment_snippet(self, obj):
        if not obj.comment:
            return mark_safe('<span class="text-base-400">—</span>')
        return obj.comment[:60] + '…' if len(obj.comment) > 60 else obj.comment
