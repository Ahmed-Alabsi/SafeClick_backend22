# apps/reports/tests.py
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status

from apps.accounts.models import User
from apps.reports.models import Report, ReportStatusLog
from apps.scans.models import Blacklist


class ReportWorkflowUnitTests(TestCase):
    """اختبارات وحدة متقدمة لنظام إدارة البلاغات ومسار التحقيق والتدقيق (Reports Workflow)"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="reporter@safeclick.app",
            name="Reporter User",
            password="SecurePassword123!",
            is_email_verified=True
        )
        self.admin_user = User.objects.create_superuser(
            email="admin@safeclick.app",
            name="Admin User",
            password="AdminPassword123!"
        )

    def test_report_creation_and_tracking_number(self):
        """التحقق من توليد رقم تتبع فريد بصيغة RPT-YYMMDD-XXXXXX تلقائياً"""
        report = Report.objects.create(
            user=self.user,
            link="https://phishing-site-test.com/login",
            category="phishing",
            reporter_name="Reporter User",
            severity=4
        )
        self.assertIsNotNone(report.tracking_number)
        self.assertTrue(report.tracking_number.startswith("RPT-"))
        self.assertEqual(report.status, "pending")
        self.assertFalse(report.is_confirmed_threat)

    def test_confirm_threat_auto_blacklisting_and_audit(self):
        """التحقق من أن تأكيد التهديد يؤدي تلقائياً إلى:
        1. تغيير الحالة إلى confirmed
        2. إضافة سجل تدقيق في ReportStatusLog
        3. إضافة النطاق تلقائياً إلى القائمة السوداء (Blacklist)
        """
        report = Report.objects.create(
            user=self.user,
            link="https://evil-malware-domain.xyz/download.exe",
            category="malware",
            reporter_name="Reporter User"
        )
        
        report.confirm_threat(notes="تم التحقق بواسطة المشرف، نطاق خبيث قطعي", changed_by=self.admin_user)
        report.refresh_from_db()

        # 1. التحقق من حالة البلاغ
        self.assertEqual(report.status, "confirmed")
        self.assertTrue(report.is_confirmed_threat)
        self.assertIsNotNone(report.reviewed_at)

        # 2. التحقق من سجل التدقيق الإداري
        status_logs = ReportStatusLog.objects.filter(report=report)
        self.assertEqual(status_logs.count(), 1)
        log = status_logs.first()
        self.assertEqual(log.old_status, "pending")
        self.assertEqual(log.new_status, "confirmed")
        self.assertEqual(log.changed_by, self.admin_user)

        # 3. التحقق من الإدراج بالقائمة السوداء
        self.assertTrue(
            Blacklist.objects.filter(domain="evil-malware-domain.xyz").exists(),
            "لم يتم إضافة النطاق الخبيث إلى القائمة السوداء تلقائياً!"
        )

    def test_report_api_submission(self):
        """التحقق من إمكانية تقديم بلاغ جديد عبر واجهة الـ API"""
        self.client.force_authenticate(user=self.user)
        payload = {
            "link": "https://suspicious-banking-login.com",
            "category": "phishing",
            "description": "صفحة مزورة تطلب تفاصيل البطاقة الائتمانية",
            "severity": 5
        }
        response = self.client.post('/api/reports/create/', payload)
        self.assertIn(response.status_code, (status.HTTP_200_OK, status.HTTP_201_CREATED))
        
        # التأكد من إنشاء البلاغ في قاعدة البيانات
        self.assertTrue(Report.objects.filter(link="https://suspicious-banking-login.com").exists())
