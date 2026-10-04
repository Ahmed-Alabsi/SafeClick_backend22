# SafeClick Changelog

All notable changes to the SafeClick platform remediation and security hardening are documented in this file.

## [Phase 1] - Security Hardening (تقوية أمنية شاملة)

### Security Fixes
- **SEC-H03 (`apps/accounts/views.py`)**: Imported `google.oauth2.id_token` and `google.auth.transport.requests` with graceful fallback and availability checks, preventing `NameError` crashes in `GoogleLoginView`. Added automated mock and validation tests.
- **SEC-H04 (`apps/scans/threat_detection.py`)**: Added missing `import tldextract` at module level, eliminating silent `NameError` fallback to unparsed netloc URLs during threat detection.
- **SEC-H02 (`safeclick/settings.py`, `apps/accounts/views.py`, `apps/scans/views.py`)**: Separated Guest JWT signing key (`GUEST_JWT_SECRET`) from application `SECRET_KEY`. Enforced strict audience (`safeclick-client`), issuer (`safeclick-backend`), and 48-hour expiration TTL.
- **SEC-M04 (`apps/scans/views.py`, `apps/domains/apps.py`)**: Removed 107 lines of terminal `safe_print` and module `print()` calls in favor of non-blocking structured `logger.debug` and `logger.info`.
- **SEC-H05 (`apps/reports/models.py`)**: Replaced predictable pseudo-random PRNG in `_generate_tracking_number` with CSPRNG `secrets.token_hex(4).upper()`.
- **SEC-H06 (`apps/scans/views.py`)**: Formally documented the rationale behind empty `authentication_classes = []` in `ScanLinkView` and `ScanHistoryView`.

### Quality & Tests
- Added `test_google_login_missing_token` and `test_google_login_success_mocked` in `apps/accounts/tests.py`.
- Added `test_guest_jwt_signed_with_wrong_key_rejected` in `apps/scans/tests.py`.
- Verified CSPRNG tracking generation in `apps/reports/tests.py`.
- Ran Bandit SAST: 0 High, 0 Critical vulnerabilities.

---

## [Phase 0] - Emergency Security Fixes (🚨 طوارئ أمنية)

### Security Fixes
- **SEC-C01 (`safeclick/settings.py`)**: Removed hardcoded `'123456'` default fallback password for PostgreSQL. Added a strict production safety net that immediately aborts startup if mandatory secrets (`SECRET_KEY`, `DB_PASSWORD`, `DB_HOST`) are absent in production mode.
- **SEC-C02 (`apps/accounts/views.py`)**: Fixed plaintext OTP assignment in `ResendOTPView` by replacing `verification.otp = otp` with `verification.set_otp(otp)`, guaranteeing cryptographic PBKDF2 hashing for all re-sent verification codes.
- **SEC-C03 (`apps/accounts/models.py` & `management/commands/rehash_otps.py`)**: Removed plaintext comparison bypass branch (`if self.otp == raw_otp: return True`) in `EmailVerification.check_otp()`. Added database management command `rehash_otps` to migrate any legacy plaintext codes.
- **SEC-C04 (`apps/scans/views.py`)**: Secured `ScanHistoryView` by enforcing explicit JWT authentication for registered users and cryptographic guest session validation, preventing unauthorized access or cross-tenant scan leakage.

### Quality & Tests
- Updated `apps/accounts/tests.py` with test cases `test_otp_secure_hashing_and_no_plaintext_bypass` and `test_resend_otp_stores_hashed_otp`.
- Updated `apps/scans/tests.py` with multi-tenant and anonymous boundary assertions in `test_scan_history_isolation`.
- Executed Bandit SAST scan: 0 High, 0 Critical vulnerabilities identified in scanned modules.
