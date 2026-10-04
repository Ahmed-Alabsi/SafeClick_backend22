# apps/scans/tests/test_decision_engine.py
from django.test import SimpleTestCase
from services.decision_engine import DecisionEngine


class DecisionEngineUnitTests(SimpleTestCase):
    """اختبارات وحدة متقدمة لمحرك اتخاذ القرار (Decision Engine)"""

    def test_phase1_blacklisted_domain_early_exit(self):
        """التحقق من أن النطاق المحظور مسبقاً يخرج مباشرة بأعلى درجة خطورة 100"""
        decision, score = DecisionEngine.evaluate_phase1(
            is_blacklisted=True,
            is_whitelisted=False,
            phishing_patterns={},
            url_features={}
        )
        self.assertEqual(decision, 'BLACKLISTED')
        self.assertEqual(score, 100)

    def test_phase1_whitelisted_clean_early_exit(self):
        """التحقق من أن النطاق الموثوق والنظيف يخرج بمسار سريع دون هدر موارد الفحص"""
        decision, score = DecisionEngine.evaluate_phase1(
            is_blacklisted=False,
            is_whitelisted=True,
            phishing_patterns={'details': {'keyword_count': 0, 'suspicious_tld': False}},
            url_features={'details': {'has_at_symbol': False, 'is_ip': False}}
        )
        self.assertEqual(decision, 'WHITELISTED_CLEAN')
        self.assertEqual(score, 0)

    def test_phase1_suspicious_features_escalation(self):
        """التحقق من تصعيد درجة الاشتباه عند وجود علامات تصيد صريحة"""
        decision, score = DecisionEngine.evaluate_phase1(
            is_blacklisted=False,
            is_whitelisted=False,
            phishing_patterns={'details': {'keyword_count': 2, 'suspicious_tld': True}},
            url_features={'details': {'has_at_symbol': True, 'is_ip': True}}
        )
        self.assertEqual(decision, 'NEEDS_ANALYSIS')
        # score = 15*2 (keywords) + 25 (tld) + 40 (@ symbol) + 35 (ip) = 130
        self.assertGreaterEqual(score, 100)

    def test_should_run_ai_logic(self):
        """التحقق من شروط استدعاء نموذج الذكاء الاصطناعي (AI Classifier)"""
        # في الفحص العميق (Deep Scan): يجب تفعيل الـ AI دائماً
        self.assertTrue(DecisionEngine.should_run_ai(scan_level='deep', heuristic_score=0, phase2_results=[]))

        # عند وجود اشتباه هيورستي متوسط أو عالي: يجب تفعيله
        self.assertTrue(DecisionEngine.should_run_ai(scan_level='standard', heuristic_score=35, phase2_results=[]))

        # عند النطاقات النظيفة تماماً في الفحص العادي: يتم تجاوزه لتوفير الموارد
        self.assertFalse(DecisionEngine.should_run_ai(scan_level='standard', heuristic_score=0, phase2_results=[]))

    def test_critical_source_floor_enforcement(self):
        """التحقق من أن رصد مصادر التهديد الحرجة (GSB / VT) يفرض حداً أدنى صارماً للنتيجة"""
        sources = [
            {'source_type': 'gsb', 'risk_score': 90, 'confidence': 0.95, 'verdict': 'malicious'},
            {'source_type': 'engines', 'risk_score': 10, 'confidence': 0.8, 'verdict': 'safe'},
            {'source_type': 'heuristic', 'risk_score': 0, 'confidence': 0.5, 'verdict': 'safe'}
        ]
        decision = DecisionEngine.aggregate_results(sources, domain_intel={}, scan_level='standard')
        
        # لا يمكن تخفيف درجة GSB بأي نتائج أخرى أقل
        self.assertGreaterEqual(decision['overall_risk_score'], 80)
        self.assertEqual(decision['final_verdict'], 'malicious')

    def test_zero_day_threat_anti_dilution(self):
        """التحقق من مبدأ Anti-Dilution: خلو VT لا يخفف تهديد الصفر-يوم المكتشف داخلياً"""
        sources = [
            # محركاتنا الداخلية كشفت تزييفاً خطيراً للعلامة التجارية
            {
                'source_type': 'engines',
                'risk_score': 85,
                'confidence': 0.9,
                'verdict': 'suspicious',
                'raw_data': {
                    'engines': {
                        'typosquatting': {'details': {'is_typosquatting': True, 'brand_impersonation': True}}
                    }
                }
            },
            # VirusTotal لم يسجل الموقع بعد لأنه هجوم جديد (Zero-Day)
            {'source_type': 'vt', 'risk_score': 0, 'confidence': 0.8, 'verdict': 'safe'}
        ]
        decision = DecisionEngine.aggregate_results(sources, domain_intel={}, scan_level='standard')

        # يجب ألا تنخفض الدرجة بسبب حداثة التهديد على VT
        self.assertGreaterEqual(decision['overall_risk_score'], 70)
        self.assertIn(decision['final_verdict'], ('suspicious', 'malicious'))

    def test_whitelisted_fast_path_heuristic_override(self):
        """التحقق من أن النطاقات المعتمدة في الـ Whitelist تبطل ضجيج الهيورستك الزائف"""
        sources = [
            {'source_type': 'heuristic', 'risk_score': 40, 'confidence': 0.6, 'verdict': 'suspicious'},
            {
                'source_type': 'engines',
                'risk_score': 0,
                'confidence': 0.95,
                'verdict': 'safe',
                'raw_data': {'engines': {'fast_path': True}}
            }
        ]
        decision = DecisionEngine.aggregate_results(sources, domain_intel={}, scan_level='standard')
        self.assertEqual(decision['overall_risk_score'], 0)
        self.assertEqual(decision['final_verdict'], 'safe')
