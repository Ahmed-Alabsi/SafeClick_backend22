# apps/accounts/tests.py
import uuid
import jwt
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from rest_framework_simplejwt.exceptions import TokenError

from .models import User, EmailVerification, GuestSession
from .serializers import RegisterSerializer, SendOTPSerializer


class AccountSecurityTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.test_password = "SecurePassword123!"
        self.user = User.objects.create_user(
            email="testuser@safeclick.app",
            name="Test User",
            password=self.test_password,
            is_email_verified=True
        )

    def test_password_minimum_length_policy(self):
        """R007: التأكد من رفض كلمات المرور الأقل من 8 أحرف وفق NIST SP 800-63B"""
        short_data = {
            'email': 'short@safeclick.app',
            'name': 'Short PW',
            'password': '12345',
            'password_confirm': '12345'
        }
        serializer = RegisterSerializer(data=short_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("8 أحرف على الأقل", str(serializer.errors))

        valid_data = {
            'email': 'valid@safeclick.app',
            'name': 'Valid PW',
            'password': 'SecurePass8!',
            'password_confirm': 'SecurePass8!'
        }
        valid_serializer = RegisterSerializer(data=valid_data)
        self.assertTrue(valid_serializer.is_valid())

    def test_otp_secure_hashing_and_no_plaintext_bypass(self):
        """SEC-C02 & SEC-C03: التحقق من تجزئة وتشفير الـ OTP ومنع أي تجاوز بالنص الواضح"""
        verification = EmailVerification.objects.create(
            email="otp_test@safeclick.app",
            name="OTP User"
        )
        raw_otp = "854921"
        verification.set_otp(raw_otp)
        verification.save()

        # التأكد من أن الرمز لا يُخزن كنص واضح ومحمي بالهاش
        self.assertNotEqual(verification.otp, raw_otp)
        self.assertTrue(verification.check_otp(raw_otp))
        self.assertFalse(verification.check_otp("000000"))

        # منع التجاوز بالنص الواضح (Plaintext Bypass Prevention)
        verification.otp = "123456"
        verification.save()
        self.assertFalse(verification.check_otp("123456"))

    def test_resend_otp_stores_hashed_otp(self):
        """SEC-C02: التأكد من أن ResendOTPView يخزن رمز OTP مشفراً وليس كنص واضح"""
        from datetime import timedelta
        from django.utils import timezone
        verification = EmailVerification.objects.create(
            email="resend_otp_test@safeclick.app",
            name="Resend User"
        )
        EmailVerification.objects.filter(pk=verification.pk).update(
            last_request_at=timezone.now() - timedelta(seconds=120)
        )
        verification.set_otp("111111")
        verification.save(update_fields=['otp'])

        resp = self.client.post('/api/auth/resend-otp/', {'email': "resend_otp_test@safeclick.app"})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        verification.refresh_from_db()
        # OTP must be hashed (starts with algorithm or does not equal 6-digit plaintext)
        self.assertFalse(verification.otp.isdigit())
        self.assertTrue(verification.otp.startswith('pbkdf2_') or verification.otp.startswith('bcrypt') or len(verification.otp) > 20)


    def test_login_user_enumeration_prevention(self):
        """R016: منع هجوم User Enumeration في تسجيل الدخول عبر توحيد رسائل الخطأ"""
        # محاولة بريد غير مسجل
        resp = self.client.post('/api/auth/login/', {
            'email': 'nonexistent@safeclick.app',
            'password': 'AnyPassword123!'
        })
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("البريد الإلكتروني أو كلمة المرور غير صحيحة", str(resp.data))

        # محاولة اسم مستخدم غير مسجل
        resp_user = self.client.post('/api/auth/login/', {
            'username': 'nonexistent_username',
            'password': 'AnyPassword123!'
        })
        self.assertEqual(resp_user.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("اسم المستخدم أو كلمة المرور غير صحيحة", str(resp_user.data))

    def test_forgot_password_enumeration_prevention(self):
        """R011: منع User Enumeration في شاشة استعادة كلمة المرور"""
        # طلب لبريد غير مسجل يجب أن يعود بـ 200 ونفس الاستجابة
        resp = self.client.post('/api/auth/forgot-password/', {
            'email': 'unregistered@safeclick.app'
        })
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data.get('message'), 'verification_sent')

    def test_logout_token_blacklisting(self):
        """R010: التحقق من إبطال Refresh Token عند تسجيل الخروج"""
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        logout_resp = self.client.post('/api/auth/logout/', {
            'refresh': str(refresh)
        })
        self.assertEqual(logout_resp.status_code, status.HTTP_200_OK)
        self.assertTrue(logout_resp.data.get('success'))

        # محاولة استخدام الـ refresh token بعد تسجيل الخروج يجب أن تفشل
        with self.assertRaises(TokenError):
            RefreshToken(str(refresh)).check_blacklist()

    def test_guest_session_registration(self):
        """R009: التحقق من إنشاء جلسة زائر مشفرة وتضمين jti في التوكن"""
        resp = self.client.post('/api/auth/guest/register/')
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn('access_token', resp.data)
        self.assertIn('guest_id', resp.data)

        guest_uuid = resp.data['guest_id']
        token_str = resp.data['access_token']

        # فك تشفير التوكن والتحقق من الحقول الأمنية ومفتاح التوقيع المستقل (SEC-H02)
        guest_secret = getattr(settings, 'GUEST_JWT_SECRET', settings.SECRET_KEY + '-guest-ns')
        payload = jwt.decode(
            token_str,
            guest_secret,
            algorithms=['HS256'],
            audience='safeclick-client',
            issuer='safeclick-backend',
        )
        self.assertEqual(payload.get('guest_id'), guest_uuid)
        self.assertTrue(payload.get('is_guest'))
        self.assertIn('jti', payload)

        # التأكد من استحالة فك التشفير بمفتاح SECRET_KEY العام (عزل أمني تام)
        with self.assertRaises(jwt.exceptions.InvalidSignatureError):
            jwt.decode(token_str, settings.SECRET_KEY, algorithms=['HS256'], audience='safeclick-client')

        # التأكد من وجود جلسة زائر نشطة في قاعدة البيانات
        self.assertTrue(GuestSession.objects.filter(id=guest_uuid, is_active=True).exists())

    def test_user_serializer_read_only_protection(self):
        """H1 Remediation: التأكد من منع المستخدم من تعديل حالة التحقق من البريد أو العدادات عبر Profile PATCH"""
        user2 = User.objects.create_user(
            email="unverified@safeclick.app",
            name="Unverified User",
            password="SecurePassword123!",
            is_email_verified=False
        )
        refresh = RefreshToken.for_user(user2)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(refresh.access_token)}')

        # محاولة تصعيد الصلاحيات وتغيير is_email_verified وعدادات الروابط
        patch_payload = {
            'name': 'Updated Name',
            'is_email_verified': True,
            'scanned_links': 9999,
            'detected_threats': 555
        }
        resp = self.client.patch('/api/auth/profile/', patch_payload, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        user2.refresh_from_db()
        self.assertEqual(user2.name, 'Updated Name')
        self.assertFalse(user2.is_email_verified, "is_email_verified was modified via PATCH!")
        self.assertEqual(user2.scanned_links, 0, "scanned_links was modified via PATCH!")
        self.assertEqual(user2.detected_threats, 0, "detected_threats was modified via PATCH!")

    def test_verify_reset_otp_lockout_after_five_attempts(self):
        """H4 Remediation: التحقق من حظر محاولات تخمين OTP لاستعادة كلمة المرور بعد 5 محاولات فاشلة"""
        verification = EmailVerification.objects.create(
            email=self.user.email,
            purpose='reset'
        )
        verification.set_otp("654321")
        verification.save()

        # إرسال 4 محاولات خاطئة (يجب أن تعود بـ 400)
        for i in range(4):
            resp = self.client.post('/api/auth/verify-reset-otp/', {
                'email': self.user.email,
                'otp': '000000'
            })
            self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

        # المحاولة الخامسة الخاطئة يجب أن تعود بـ 403 Forbidden وتفعل الحظر
        resp5 = self.client.post('/api/auth/verify-reset-otp/', {
            'email': self.user.email,
            'otp': '000000'
        })
        self.assertEqual(resp5.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("حظر", str(resp5.data))

        # المحاولة السادسة حتى لو كانت صحيحة يجب أن تُرفض بالحظر
        resp6 = self.client.post('/api/auth/verify-reset-otp/', {
            'email': self.user.email,
            'otp': '654321'
        })
        self.assertEqual(resp6.status_code, status.HTTP_403_FORBIDDEN)

    def test_reset_password_nist_validation(self):
        """H4 Remediation: التحقق من إلزام كلمة المرور الجديدة بمعايير NIST (8 أحرف على الأقل)"""
        verification = EmailVerification.objects.create(
            email=self.user.email,
            purpose='reset'
        )
        verification.set_otp("999888")
        verification.save()

        # محاولة تعيين كلمة مرور ضعيفة أقل من 8 أحرف
        weak_resp = self.client.post('/api/auth/reset-password/', {
            'email': self.user.email,
            'otp': '999888',
            'password': 'short'
        })
        self.assertEqual(weak_resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("8 أحرف على الأقل", str(weak_resp.data))

        # محاولة تعيين كلمة مرور صالحة وقوية
        strong_resp = self.client.post('/api/auth/reset-password/', {
            'email': self.user.email,
            'otp': '999888',
            'password': 'NewSuperSecurePass2026!'
        })
        self.assertEqual(strong_resp.status_code, status.HTTP_200_OK)

        # التحقق من قدرة المستخدم على تسجيل الدخول بكلمة المرور الجديدة
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewSuperSecurePass2026!'))

    def test_register_view_enforces_email_verification(self):
        """H1 Remediation: التأكد من أن مسار RegisterView لا ينشئ مستخدماً نشطاً أو JWT دون تحقق OTP"""
        reg_payload = {
            'name': 'New Secure User',
            'email': 'new_secure@safeclick.app',
            'password': 'StrongPassword2026!',
            'password_confirm': 'StrongPassword2026!'
        }
        resp = self.client.post('/api/auth/register/', reg_payload, format='json')
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertTrue(resp.data.get('requires_verification'))
        self.assertEqual(resp.data.get('message'), 'verification_sent')
        self.assertNotIn('tokens', resp.data)

        # المستخدم لم يُنشأ بعد في جدول User
        self.assertFalse(User.objects.filter(email='new_secure@safeclick.app').exists())

        # طلب التحقق محفوظ في EmailVerification
        verification = EmailVerification.objects.get(email='new_secure@safeclick.app')
        self.assertEqual(verification.purpose, 'register')
        self.assertEqual(verification.name, 'New Secure User')

    def test_login_view_rejects_unverified_email(self):
        """H1 Remediation: التأكد من رفض تسجيل دخول أي حساب لم يكتمل التحقق من بريده الإلكتروني"""
        User.objects.create_user(
            email="unverified_login@safeclick.app",
            name="Unverified Login",
            password="StrongPassword2026!",
            is_email_verified=False
        )
        resp = self.client.post('/api/auth/login/', {
            'email': 'unverified_login@safeclick.app',
            'password': 'StrongPassword2026!'
        })
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(resp.data.get('code'), 'email_not_verified')

    def test_google_login_missing_token(self):
        """SEC-H03: التحقق من معالجة GoogleLoginView لغياب التوكن دون حدوث NameError أو انهيار"""
        resp = self.client.post('/api/auth/google/', {})
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(resp.data.get('success'))

    def test_google_login_success_mocked(self):
        """SEC-H03: التحقق من نجاح تسجيل الدخول بجوجل وإنشاء حساب موثق وتوليد JWT"""
        from unittest.mock import patch
        mock_idinfo = {
            'iss': 'https://accounts.google.com',
            'email': 'oauth_verified@safeclick.app',
            'name': 'OAuth Google User'
        }
        with patch('apps.accounts.views.id_token.verify_oauth2_token', return_value=mock_idinfo):
            resp = self.client.post('/api/auth/google/', {'id_token': 'fake_valid_google_token_xyz'})
            self.assertEqual(resp.status_code, status.HTTP_200_OK)
            self.assertTrue(resp.data.get('success'))
            self.assertIn('tokens', resp.data)
            self.assertTrue(User.objects.filter(email='oauth_verified@safeclick.app', is_email_verified=True).exists())


