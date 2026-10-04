# apps/scans/tests.py
import uuid
import jwt
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User, GuestSession
from apps.scans.models import Scan
from apps.scans.views import get_valid_guest_id


class ScanEngineSecurityTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="scanner@safeclick.app",
            name="Scanner User",
            password="SecurePassword123!",
            is_email_verified=True
        )
        self.guest = GuestSession.objects.create()

    def test_forged_guest_id_rejected(self):
        """R019: التحقق من رفض أي معرف زائر عشوائي مزور غير مسجل في قاعدة البيانات"""
        class FakeRequest:
            headers = {"X-Guest-ID": str(uuid.uuid4())}

        result = get_valid_guest_id(FakeRequest())
        self.assertIsNone(result)

    def test_valid_guest_id_accepted(self):
        """التحقق من قبول معرف الزائر الحقيقي والمسجل في قاعدة البيانات"""
        class ValidHeaderRequest:
            headers = {"X-Guest-ID": str(self.guest.id)}

        result = get_valid_guest_id(ValidHeaderRequest())
        self.assertEqual(result, self.guest.id)

    def test_valid_guest_jwt_accepted(self):
        """التحقق من قبول التوكن الموقع للزائر المسجل في قاعدة البيانات بمفتاح GUEST_JWT_SECRET"""
        payload = {
            'guest_id': str(self.guest.id),
            'jti': str(uuid.uuid4()),
            'is_guest': True,
            'iss': 'safeclick-backend',
            'aud': 'safeclick-client',
        }
        guest_secret = getattr(settings, 'GUEST_JWT_SECRET', settings.SECRET_KEY + '-guest-ns')
        token = jwt.encode(payload, guest_secret, algorithm='HS256')

        class ValidJWTRequest:
            headers = {"Authorization": f"Bearer {token}"}

        result = get_valid_guest_id(ValidJWTRequest())
        self.assertEqual(result, self.guest.id)

    def test_guest_jwt_signed_with_wrong_key_rejected(self):
        """SEC-H02: التحقق من رفض أي توكن زائر غير موقع بـ GUEST_JWT_SECRET (حتى لو وُقّع بـ SECRET_KEY)"""
        payload = {
            'guest_id': str(self.guest.id),
            'jti': str(uuid.uuid4()),
            'is_guest': True,
            'iss': 'safeclick-backend',
            'aud': 'safeclick-client',
        }
        # توقيع بـ SECRET_KEY العام بدلاً من مفتاح الزائر المنفصل
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

        class ForgedSecretRequest:
            headers = {"Authorization": f"Bearer {token}"}

        result = get_valid_guest_id(ForgedSecretRequest())
        self.assertIsNone(result)

    def test_scan_history_isolation(self):
        """التحقق من عزل سجل الفحوصات بين المستخدمين والزوار"""
        # إنشاء فحص للمستخدم
        user_scan = Scan.objects.create(
            user=self.user,
            url="https://legitimate-site.com",
            result="safe",
            safe=True,
            risk_score=0
        )

        # إنشاء فحص للزائر
        guest_scan = Scan.objects.create(
            guest_id=self.guest.id,
            url="https://another-site.com",
            result="safe",
            safe=True,
            risk_score=5
        )

        # 1. طلب من مستخدم مسجل
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(refresh.access_token)}')
        resp_user = self.client.get('/api/scans/history/')
        self.assertEqual(resp_user.status_code, status.HTTP_200_OK)
        urls = [item['url'] for item in resp_user.data.get('history', [])]
        self.assertIn("https://legitimate-site.com", urls)
        self.assertNotIn("https://another-site.com", urls)

        # 2. طلب من زائر مسجل
        self.client.credentials(HTTP_X_GUEST_ID=str(self.guest.id))
        resp_guest = self.client.get('/api/scans/history/')
        self.assertEqual(resp_guest.status_code, status.HTTP_200_OK)
        guest_urls = [item['url'] for item in resp_guest.data.get('history', [])]
        self.assertIn("https://another-site.com", guest_urls)
        self.assertNotIn("https://legitimate-site.com", guest_urls)

        # 3. طلب بدون هوية إطلاقاً (Anonymous without user or guest id)
        self.client.credentials()
        resp_anon = self.client.get('/api/scans/history/')
        self.assertEqual(resp_anon.status_code, status.HTTP_200_OK)
        self.assertEqual(resp_anon.data.get('history', []), [])
        self.assertEqual(resp_anon.data.get('count', 0), 0)

    def test_blacklist_overrides_cached_safe_scan(self):
        """H2 Remediation: التأكد من أن القائمة السوداء تلغي فوراً أي نتيجة كاش سابقة حتى لو كانت آمنة"""
        import hashlib
        from datetime import timedelta
        from django.utils import timezone
        from apps.scans.models import ScanCache, Blacklist
        from services.scan_orchestrator import ScanOrchestrator

        target_url = "https://previously-safe-site.com"
        target_hash = hashlib.sha256(target_url.encode('utf-8')).hexdigest()

        # 1. تجهيز نتيجة كاش "آمنة" مسبقة
        ScanCache.objects.create(
            url=target_url,
            url_hash=target_hash,
            scan_level='basic',
            result='safe',
            threat_level='none',
            risk_score=0,
            expires_at=timezone.now() + timedelta(hours=1)
        )

        # 2. إضافة الدومين إلى القائمة السوداء لاحقاً
        Blacklist.objects.create(
            link=target_url,
            domain="previously-safe-site.com",
            threat_type="Phishing",
            severity=5,
            is_active=True
        )

        # 3. الفحص يجب أن يعيد نتيجة 'malicious' فوراً ويلغي الكاش
        orchestrator = ScanOrchestrator(request_user=self.user)
        result = orchestrator.scan(target_url, scan_level='basic', ignore_cache=False)

        self.assertEqual(result.get('result'), 'dangerous') # Flutter verdict
        self.assertEqual(result.get('risk_score'), 100)
        self.assertFalse(result.get('cached'))

    def test_blacklist_signal_invalidates_scan_cache(self):
        """M4 Remediation: إشارة حفظ القائمة السوداء تحذف كاش الفحص للدومين المعني تلقائياً"""
        import hashlib
        from datetime import timedelta
        from django.utils import timezone
        from apps.scans.models import ScanCache, Blacklist

        url = "https://bad-portal.xyz/login"
        url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()

        ScanCache.objects.create(
            url=url,
            url_hash=url_hash,
            scan_level='basic',
            result='safe',
            threat_level='none',
            risk_score=0,
            expires_at=timezone.now() + timedelta(hours=1)
        )
        self.assertTrue(ScanCache.objects.filter(url_hash=url_hash).exists())

        # حفظ عنصر جديد بالقائمة السوداء
        Blacklist.objects.create(
            link=url,
            domain="bad-portal.xyz",
            threat_type="Malware",
            severity=4,
            is_active=True
        )

        # الإشارة يجب أن تحذف سجل الكاش
        self.assertFalse(ScanCache.objects.filter(url_hash=url_hash).exists())

    def test_expired_blacklist_does_not_block(self):
        """التحقق من أن عناصر القائمة السوداء المنتهية الصلاحية لا تحظر النطاق خطأ"""
        from datetime import timedelta
        from django.utils import timezone
        from apps.scans.models import Blacklist
        from services.scan_orchestrator import ScanOrchestrator

        url = "https://clean-sample.org"
        Blacklist.objects.create(
            link=url,
            domain="clean-sample.org",
            threat_type="Temporary Block",
            severity=2,
            is_active=True,
            expires_at=timezone.now() - timedelta(days=1)  # منتهي الصلاحية
        )

        orchestrator = ScanOrchestrator(request_user=self.user)
        result = orchestrator.scan(url, scan_level='basic', ignore_cache=True)
        self.assertNotEqual(result.get('risk_score'), 100)

    def test_ssrf_url_validation(self):
        """C1 Remediation: التحقق من منع ثغرات SSRF وعناوين الـ IP الخاصة وحسابات البيانات المدمجة"""
        from apps.common.url_validator import is_safe_redirect_url

        dangerous_urls = [
            "http://127.0.0.1/admin",
            "http://localhost:8000/",
            "http://0.0.0.0:80/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://10.0.0.1/secret",
            "http://192.168.1.1/router",
            "http://172.16.0.1/internal",
            "http://user:password@malicious-site.com/",
            "ftp://files.example.com",
            "file:///etc/passwd",
            "http://server.local/",
            "http://app.internal/",
        ]

        for u in dangerous_urls:
            safe, reason = is_safe_redirect_url(u)
            self.assertFalse(safe, f"Should reject SSRF URL {u} but was accepted")

        safe_urls = [
            "https://google.com",
            "https://saudi.gov.sa/portal",
            "https://alrajhibank.com.sa",
        ]
        for u in safe_urls:
            safe, reason = is_safe_redirect_url(u)
            self.assertTrue(safe, f"Should accept safe URL {u} but failed: {reason}")

    def test_guest_quota_atomic_enforcement(self):
        """H5 Remediation: التحقق من القفل الذري لحصة الزائر ومنع تجاوز الحد المجاني عند الطلبات المتزامنة"""
        from apps.accounts.models import GuestSession

        guest = GuestSession.objects.create()

        # استهلاك 3 فحوصات متتالية بنجاح
        for i in range(1, 4):
            allowed, count = GuestSession.check_and_increment_quota(guest.id, limit=3)
            self.assertTrue(allowed)
            self.assertEqual(count, i)

        # المحاولة الرابعة يجب أن تُرفض بشكل قاطع
        allowed, count = GuestSession.check_and_increment_quota(guest.id, limit=3)
        self.assertFalse(allowed)
        self.assertEqual(count, 3)

        # فحص استجابة الـ API عند وصول زائر استنفد حصته
        self.client.credentials(HTTP_X_GUEST_ID=str(guest.id))
        resp = self.client.post('/api/scans/scan/', {
            'link': 'https://example.com'
        })
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(resp.data.get('code'), 'guest_limit_reached')

    def test_scan_deduplication_local_fallback(self):
        """H5 Remediation: التحقق من آلية قفل منع تكرار الفحوصات المتزامنة حتى عند غياب Redis"""
        from services.url_scan_service import scan_url

        url = "https://dedup-test-target.com"
        res1 = scan_url(url=url, user=self.user, scan_level='basic', ignore_cache=False)
        self.assertTrue(res1.get('success'))

        # الفحص الثاني لنفس الرابط يجب أن يمر بنجاح ويعيد النتيجة من الكاش
        res2 = scan_url(url=url, user=self.user, scan_level='basic', ignore_cache=False)
        self.assertTrue(res2.get('success'))
        self.assertTrue(res2.get('meta', {}).get('cache_hit'))

    def test_bloom_filter_verified_resilience(self):
        """P0 Remediation: التحقق من صمود مرشح بلوم واعتماد النطاقات الرسمية والعالمية حتى عند غياب ملف CSV"""
        from domain_analysis.services.bloom_filter import is_legit_domain

        # نطاقات عالمية وحكومية وبنكية موثقة
        self.assertTrue(is_legit_domain('google.com'))
        self.assertTrue(is_legit_domain('alrajhibank.com.sa'))
        self.assertTrue(is_legit_domain('snb.com.sa'))
        self.assertTrue(is_legit_domain('absher.sa'))
        self.assertTrue(is_legit_domain('nafath.sa'))

        # نطاقات عشوائية غير موثقة يجب أن تُرجع False
        self.assertFalse(is_legit_domain('random-malicious-attacker-domain.xyz'))

    def test_threat_detector_vt_fail_open_hardened(self):
        """P0 Remediation: منع ثغرة الهروب الأمني (Fail-Open) عند تجاوز حدود VirusTotal وعدم منح أمان 100%"""
        from apps.scans.threat_detection import ThreatDetector

        detector = ThreatDetector()
        detector.results['threats_found'] = []
        detector.results['vt_success'] = False  # محاكاة تجاوز كوتا VT 429
        detector.results['gsb_success'] = True  # محاكاة سلامة GSB

        detector._calculate_final_score()

        # يجب تصنيف الفحص كـ "فحص جزئي" وعدم منح أمان كامل 100%
        self.assertEqual(detector.results['score'], 80)
        self.assertEqual(detector.results['final_status'], 'فحص جزئي')
        self.assertIn('VirusTotal', detector.results['final_message'])


