# SafeClick Remediation & Hardening — Execution Tasks

## Phase 0: Emergency Security Fixes (🚨 طوارئ أمنية) — [COMPLETED ✅]
- [x] **Task 0.1**: Remove default DB password & add production safety net in `safeclick/settings.py` (SEC-C01)
- [x] **Task 0.2**: Fix plaintext OTP storage in `apps/accounts/views.py` `ResendOTPView` (SEC-C02)
- [x] **Task 0.3**: Remove plaintext bypass branch in `apps/accounts/models.py` `check_otp()` & create migration command (SEC-C03)
- [x] **Task 0.4**: Add authentication & guest handling to `apps/scans/views.py` `ScanHistoryView` (SEC-C04)
- [x] **Quality Gate 0**: Run tests, check security validations, update CHANGELOG.md

## Phase 1: Security Hardening (تقوية أمنية) — [COMPLETED ✅]
- [x] Task 1.1: Fix Google Login `verify_oauth2_token` with audience and imports (SEC-H03)
- [x] Task 1.2: Fix tldextract missing import in threat detection (SEC-H04)
- [x] Task 1.3: Separate Guest JWT token from user token using GUEST_JWT_SECRET (SEC-H02)
- [x] Task 1.4: Remove production `print()` statements and replace with logger (SEC-M04)
- [x] Task 1.5: Fix insecure random tracking number in reports using CSPRNG (SEC-H05)
- [x] Task 1.6: Document manual auth rationale in `apps/scans/views.py` (SEC-H06)
- [x] **Quality Gate 1**: Run tests, check Bandit SAST, update CHANGELOG.md

## Phase 2: Architectural Unification (توحيد المعمارية) — [READY ⏳]
- [ ] Task 2.1: Single Source of Truth for engine weights (`services/scoring_config.py`)
- [ ] Task 2.2: Unified verdict thresholds across all engines
- [ ] Task 2.3: Consolidate phishing keywords & brand databases
- [ ] Task 2.4: Unified verdict terminology
- [ ] Task 2.5: Deconstruct `ScanLinkView` into Clean Architecture services
- [ ] Quality Gate 2

## Phase 3: Data Integrity & Schema Optimization (سلامة البيانات)
- [ ] Task 3.1: Clean redundant fields in `Scan` model
- [ ] Task 3.2: Database constraints & foreign key cascades
- [ ] Task 3.3: Composite database indexes for hot queries
- [ ] Quality Gate 3

## Phase 4: Infrastructure & Scalability (بنية تحتية وتوسع)
- [ ] Task 4.1: Asynchronous scan processing with Celery/Redis
- [ ] Task 4.2: Shared ThreadPoolExecutor lifecycle
- [ ] Task 4.3: Structured JSON logging
- [ ] Task 4.4: Deep health check endpoint
- [ ] Task 4.5: Request correlation IDs
- [ ] Quality Gate 4

## Phase 5: Monitoring, Observability & ML Ops (مراقبة و ML)
- [ ] Task 5.1: Prometheus metrics instrumentation
- [ ] Task 5.2: Sentry error tracking integration
- [ ] Task 5.3: ML concept drift detection
- [ ] Task 5.4: Model artifact signing & integrity verification
- [ ] Quality Gate 5
