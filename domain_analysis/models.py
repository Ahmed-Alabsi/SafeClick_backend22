from django.db import models


class DomainCache(models.Model):

    domain = models.CharField(
        max_length=255,
        unique=True,
        db_index=True
    )

    registrar = models.CharField(
        max_length=255,
        null=True,
        blank=True
    )

    creation_date = models.DateTimeField(
        null=True,
        blank=True
    )

    expiration_date = models.DateTimeField(
        null=True,
        blank=True
    )

    age_days = models.IntegerField(
        null=True
    )

    is_suspicious = models.BooleanField(
        default=False,
        db_index=True
    )

    last_checked = models.DateTimeField(
        auto_now=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        indexes = [
            models.Index(fields=["domain"]),
            models.Index(fields=["age_days"]),
        ]

    def __str__(self):
        return self.domain