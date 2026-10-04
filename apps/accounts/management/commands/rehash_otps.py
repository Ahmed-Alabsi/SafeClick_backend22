"""
Management command to rehash any legacy plaintext OTPs in EmailVerification table.
Phase 0 Security Remediation (SEC-C03).
"""
import logging
from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password, identify_hasher
from apps.accounts.models import EmailVerification

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Rehashes legacy plaintext OTPs in the EmailVerification table."

    def handle(self, *args, **options):
        self.stdout.write("Scanning EmailVerification entries for plaintext OTPs...")
        rehashed_count = 0
        skipped_count = 0

        for verification in EmailVerification.objects.all():
            if not verification.otp:
                continue

            try:
                identify_hasher(verification.otp)
                # Already hashed securely
                skipped_count += 1
            except ValueError:
                # Plaintext OTP found - rehash it
                raw_otp = verification.otp
                verification.otp = make_password(raw_otp)
                verification.save(update_fields=['otp'])
                rehashed_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully completed OTP migration: {rehashed_count} rehashed, "
                f"{skipped_count} already secure."
            )
        )
