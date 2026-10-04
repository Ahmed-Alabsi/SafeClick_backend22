# domain_analysis/tests.py
from django.test import SimpleTestCase
from domain_analysis.services.typosquatting_engine import detect_typosquatting


class TyposquattingEngineUnitTests(SimpleTestCase):
    """اختبارات وحدة متقدمة لمحرك كشف انتحال العلامات التجارية والتزييف (Typosquatting Engine)"""

    def test_direct_brand_typosquatting_detection(self):
        """التحقق من كشف محاولات التزييف المباشرة للعلامات الحساسة مثل PayPal و Google"""
        # محاولة تزييف paypal عبر الحرف 1 أو أحرف مكررة
        result = detect_typosquatting("paypa1-security.com")
        self.assertEqual(result.get("status"), "ok")
        details = result.get("details", {})
        self.assertTrue(
            details.get("is_typosquatting") or details.get("brand_impersonation"),
            "فشل في كشف محاولة انتحال بايبال"
        )

    def test_legitimate_brand_domains_not_flagged(self):
        """التحقق من عدم وسم النطاق الأصلي الشرعي كتهديد تزييف (False Positive Prevention)"""
        result = detect_typosquatting("google.com")
        self.assertEqual(result.get("status"), "ok")
        details = result.get("details", {})
        self.assertFalse(
            details.get("is_typosquatting", False),
            "تم وسم نطاق جوجل الرسمي بالخطأ كـ Typosquatting!"
        )

        fb_result = detect_typosquatting("facebook.com")
        self.assertEqual(fb_result.get("status"), "ok")
        self.assertFalse(fb_result.get("details", {}).get("is_typosquatting", False))

    def test_subdomain_brand_impersonation_detection(self):
        """التحقق من كشف العلامات التجارية المحشورة داخل نطاقات فرعية مشبوهة"""
        # مثال: إخفاء اسم العلامة التجارية في النطاق الفرعي لخداع المستخدم
        result = detect_typosquatting("paypal.login-verify-account-security.xyz")
        self.assertEqual(result.get("status"), "ok")
        details = result.get("details", {})
        self.assertTrue(
            details.get("brand_impersonation") or details.get("is_typosquatting"),
            "فشل في كشف انتحال العلامة في النطاق الفرعي"
        )

    def test_safe_handling_of_edge_cases(self):
        """التحقق من المعالجة الآمنة لحالات الإدخال الخاطئة أو الفارغة (Fail-Safe)"""
        empty_result = detect_typosquatting("")
        self.assertEqual(empty_result.get("status"), "error")
        self.assertFalse(empty_result.get("details", {}).get("is_typosquatting", False))

        none_result = detect_typosquatting(None)
        self.assertEqual(none_result.get("status"), "error")

    def test_regional_brand_typosquatting_detection(self):
        """التحقق من كشف انتحال العلامات الإقليمية والمحلية (الراجحي، أبشر، نفاذ، إس تي سي باي)"""
        # محاولة تزييف مصرف الراجحي
        alrajhi_fake = detect_typosquatting("alrajhibank-login-portal.xyz")
        self.assertEqual(alrajhi_fake.get("status"), "ok")
        self.assertTrue(
            alrajhi_fake.get("details", {}).get("is_typosquatting") or 
            alrajhi_fake.get("details", {}).get("brand_impersonation"),
            "فشل في كشف انتحال مصرف الراجحي"
        )

        # محاولة تزييف منصة أبشر الحكومية
        absher_fake = detect_typosquatting("absher-sa-verification.com")
        self.assertEqual(absher_fake.get("status"), "ok")
        self.assertTrue(
            absher_fake.get("details", {}).get("is_typosquatting") or 
            absher_fake.get("details", {}).get("brand_impersonation"),
            "فشل في كشف انتحال منصة أبشر"
        )

    def test_regional_legitimate_domains_not_flagged(self):
        """التحقق من عدم وسم النطاقات الإقليمية الرسمية كـ Typosquatting (False Positive Prevention)"""
        legit_domains = [
            "alrajhibank.com.sa",
            "absher.sa",
            "stc.com.sa",
            "nafath.sa",
            "noon.com"
        ]
        for domain in legit_domains:
            res = detect_typosquatting(domain)
            self.assertEqual(res.get("status"), "ok")
            self.assertFalse(
                res.get("details", {}).get("is_typosquatting", False),
                f"تم وسم النطاق الرسمي {domain} بالخطأ كـ Typosquatting!"
            )

    def test_short_brand_token_boundary_detection(self):
        """التحقق من كشف العلامات المكونة من 3 أحرف (snb, cib, anb, stc) بدقة عالية"""
        # محاولات انتحال صريحة للبنك الأهلي والـ CIB والعربي
        test_cases = [
            ("snb-login-portal.xyz", "snb"),
            ("snb.secure-login-sa.com", "snb"),
            ("cib-online-verification.com", "cib"),
            ("anb-banking-portal.xyz", "anb"),
            ("stc-pay-sa-bill.xyz", "stc"),
        ]
        for domain, expected_brand in test_cases:
            res = detect_typosquatting(domain)
            self.assertEqual(res.get("status"), "ok")
            details = res.get("details", {})
            self.assertTrue(
                details.get("is_typosquatting") or details.get("brand_impersonation"),
                f"فشل في كشف انتحال العلامة القصيرة {expected_brand} في {domain}"
            )
            self.assertEqual(
                details.get("target_brand"), expected_brand,
                f"العلامة المستهدفة غير متطابقة لـ {domain}: {details.get('target_brand')}"
            )

    def test_short_brand_false_positive_prevention(self):
        """التحقق التام من عدم تصنيف الكلمات العادية أو النطاقات الرسمية كـ انتحال (Zero False Positive)"""
        # كلمات تشبه أو تحوي حروف snb/cib ولكنها ليست انتحالاً
        safe_cases = [
            "snowboard-gear.com",
            "snbx.com",
            "xsnb.com",
            "sub.example.com",
            "cibal.com",
            "anbar.com",
            # النطاقات الرسمية المعتمدة
            "snb.com.sa",
            "cibeg.com",
            "anb.com.sa",
        ]
        for domain in safe_cases:
            res = detect_typosquatting(domain)
            self.assertEqual(res.get("status"), "ok")
            details = res.get("details", {})
            self.assertFalse(
                details.get("is_typosquatting", False),
                f"إيجابية كاذبة: تم وسم النطاق السليم {domain} كـ Typosquatting بالخطأ!"
            )

