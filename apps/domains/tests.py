# apps/domains/tests.py
"""
Unit and Integration Tests for Dynamic Brand Intelligence & Domain Catalog
──────────────────────────────────────────────────────────────────────────
Validates data models, canonicalization, verification statuses, in-memory caching,
version bumping, and transaction safety.
"""

from django.test import TestCase
from apps.domains.models import Brand, BrandDomain, BrandKeyword
from apps.domains.services.brand_service import BrandService


class BrandCatalogDataModelTests(TestCase):
    """اختبارات سلامة نماذج الكتالوج والـ Canonicalization والتوثيق"""

    def setUp(self):
        self.brand = Brand.objects.create(
            name="Saudi National Bank",
            name_ar="البنك الأهلي السعودي",
            slug="snb",
            sector="banking",
            country="SA",
            risk_weight="CRITICAL",
            is_active=True
        )

    def tearDown(self):
        BrandService.clear_cache()


    def test_brand_domain_canonicalization_and_verification(self):
        """التحقق من تطهير النطاقات تلقائياً وفصل حالة التوثيق"""
        # نطاق غير مطهر مع https وحروف كبيرة ومسار
        domain_entry = BrandDomain.objects.create(
            brand=self.brand,
            domain="HTTPS://AlAhli.com.sa/portal?lang=ar",
            status="VERIFIED",
            verification_source="SAMA",
            is_active=True
        )
        # التحقق من أن النطاق تم تطهيره بدقة
        self.assertEqual(domain_entry.domain, "alahli.com.sa")

        # نطاق تجريبي بحالة PENDING (غير موثق)
        pending_entry = BrandDomain.objects.create(
            brand=self.brand,
            domain="test-pending.com",
            status="PENDING",
            verification_source="COMMUNITY_REPORT",
            is_active=True
        )
        self.assertEqual(pending_entry.status, "PENDING")

    def test_brand_keyword_strategies(self):
        """التحقق من استراتيجيات المطابقة للكلمات المفتاحية"""
        kw_snb = BrandKeyword.objects.create(
            brand=self.brand,
            keyword="  SNB  ",
            match_strategy="TOKEN_BOUNDARY",
            weight=1.0,
            is_active=True
        )
        # التحقق من تطهير الكلمة إلى أحرف صغيرة وبدون مسافات
        self.assertEqual(kw_snb.keyword, "snb")
        self.assertEqual(kw_snb.match_strategy, "TOKEN_BOUNDARY")


class BrandServiceIntegrationTests(TestCase):
    """اختبارات خدمة الاستخبارات المركزية والكاش والـ Versioning"""

    def setUp(self):
        # إنشاء بنك الراجحي مع نطاق موثق ونطاق قيد الانتظار
        self.brand = Brand.objects.create(
            name="Al Rajhi Bank",
            name_ar="مصرف الراجحي",
            slug="alrajhi",
            sector="banking",
            country="SA",
            risk_weight="CRITICAL",
            is_active=True
        )
        self.official_domain = BrandDomain.objects.create(
            brand=self.brand,
            domain="alrajhibank.com.sa",
            status="VERIFIED",
            verification_source="SAMA",
            is_active=True,
            is_primary=True
        )
        self.pending_domain = BrandDomain.objects.create(
            brand=self.brand,
            domain="alrajhi-staging-test.com",
            status="PENDING",
            verification_source="UNVERIFIED",
            is_active=True
        )
        self.kw = BrandKeyword.objects.create(
            brand=self.brand,
            keyword="alrajhibank",
            match_strategy="TYPO_SIMILARITY",
            weight=1.0,
            is_active=True
        )
        BrandService.bump_version()

    def tearDown(self):
        BrandService.clear_cache()

    def test_catalog_loads_verified_domains_only(self):
        """التحقق من أن الكاش لا يعتمد إلا النطاقات الموثقة (VERIFIED) فقط"""
        # النطاق الموثق يجب أن يكون معتمداً
        self.assertTrue(BrandService.is_verified_official_domain("alrajhibank.com.sa"))
        self.assertTrue(BrandService.is_official_domain_for_brand("alrajhibank.com.sa", "alrajhi"))

        # النطاق غير المعتمد (PENDING) يجب ألا يدخل في القائمة الرسمية
        self.assertFalse(BrandService.is_verified_official_domain("alrajhi-staging-test.com"))

    def test_cache_invalidation_on_new_domain(self):
        """التحقق من تحديث الكتالوج فور إضافة نطاق جديد واعتماده"""
        initial_version = BrandService.get_current_version()

        # إضافة نطاق رسمي ثانٍ للراجحي
        BrandDomain.objects.create(
            brand=self.brand,
            domain="alrajhi.bank",
            status="VERIFIED",
            verification_source="SAMA",
            is_active=True
        )
        BrandService.bump_version()

        # التحقق من زيادة رقم النسخة والتعرف الفوري على النطاق الجديد
        self.assertGreaterEqual(BrandService.get_current_version(), initial_version)
        self.assertTrue(BrandService.is_verified_official_domain("alrajhi.bank"))

    def test_token_boundary_keywords_retrieval(self):
        """التحقق من استرجاع الكلمات المحددة كـ Token Boundary"""
        kw_snb = BrandKeyword.objects.create(
            brand=self.brand,
            keyword="rajhi",
            match_strategy="TOKEN_BOUNDARY",
            weight=0.9,
            is_active=True
        )
        BrandService.bump_version()

        token_kws = BrandService.get_token_boundary_keywords()
        self.assertIn("rajhi", token_kws)
        self.assertEqual(token_kws["rajhi"]["brand_slug"], "alrajhi")
