# apps/feedback/models.py

from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator


class AppRating(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="app_rating",
        verbose_name='المستخدم'
    )
    rating = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        verbose_name='التقييم',
        help_text='من 1 إلى 5 نجوم'
    )
    comment = models.TextField(blank=True, verbose_name='التعليق')

    created_at = models.DateTimeField(auto_now_add=True, verbose_name='تاريخ الإنشاء')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='آخر تحديث')

    class Meta:
        verbose_name = 'تقييم التطبيق'
        verbose_name_plural = 'تقييمات التطبيق'
        constraints = [
            models.UniqueConstraint(fields=['user'], name='unique_user_rating')
        ]

    def __str__(self):
        return f"{self.user} - {self.rating}/5"


