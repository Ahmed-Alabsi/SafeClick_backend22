import socket
import requests
import logging
import time
import base64
import tldextract
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from django.conf import settings
import os
from apps.core.utils.monitoring import monitor_engine

logger = logging.getLogger(__name__)

# Global executor pool to avoid "wait at exit" overhead (Shared across instances)
# Configurable via SCAN_THREAD_WORKERS with safe default (16) to prevent thread/memory exhaustion
MAX_SCAN_WORKERS = int(os.getenv('SCAN_THREAD_WORKERS', '16'))
_executor = ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS)

class ThreatDetector:
    """محرك الكشف عن التهديدات - تنبيه: يعتمد كلياً على المصادر الخارجية (GSB/VT) بناءً على طلب المستخدم"""

    def __init__(self):
        self.results = {
            'safe': None,
            'score': 0,
            'details': [],
            'threats_found': [],
            'domain_info': {},
            'ip_info': {},
            'ip_address': None,
            'response_time': 0.0,
            'domain': '',
            'full_url': '',
            'threats_count': 0,
            'final_status': 'unknown',
            'final_message': 'جاري الفحص...',
            'scan_failed': False, # Flag to indicate if both APIs failed
        }

    SCAN_CONFIG = {
        'basic': {
            'services': ['gsb'],
            'overall_timeout': 7.0,
            'gsb_timeout': 3.0,
        },
        'standard': {
            'services': ['vt'],
            'overall_timeout': 10.0,
            'vt_timeout': 8.0,
        },
        'deep': {
            'services': ['gsb', 'vt'],
            'overall_timeout': 15.0,
            'gsb_timeout': 3.0,
            'vt_timeout': 12.0,
        }
    }

    @monitor_engine("virustotal")
    def detect(self, url: str, scan_level: str = 'deep') -> dict:
        """Run threat detection strictly using external GSB and VT lookups."""
        logger.info(f"[ThreatDetector] Starting EXTERNAL scan: {url[:80]}")
        url = self._normalize_url(url)

        try:
            extracted = tldextract.extract(url)
            full_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        except Exception:
            full_domain = urlparse(url).netloc

        self.results['domain'] = full_domain
        self.results['full_url'] = url

        # IP Resolution (for telemetry)
        try:
            hostname = urlparse(url).netloc or full_domain
            if ':' in hostname: hostname = hostname.split(':')[0]
            self.results['ip_address'] = socket.gethostbyname(hostname)
        except Exception:
            pass

        # Configuration
        if scan_level not in self.SCAN_CONFIG:
            scan_level = 'deep'
        config = self.SCAN_CONFIG[scan_level]
        
        vt_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
        gsb_key = getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', '')

        if not vt_key and not gsb_key:
             self.results['scan_failed'] = True
             self.results['details'].append("⚠️ خطأ في النظام: لا توجد مفاتيح API لخدمات الفحص")
             self._calculate_final_score()
             return self.results

        # Track which services ran and their success status
        self.results['vt_success'] = False
        self.results['gsb_success'] = False

        futures_map = {}
        if 'gsb' in config['services'] and gsb_key:
            futures_map[_executor.submit(self._check_google_safe_browsing, url, config.get('gsb_timeout', 3.0))] = 'google_safe'
        if 'vt' in config['services'] and vt_key:
            futures_map[_executor.submit(self._check_virustotal, url, config.get('vt_timeout', 15.0))] = 'virustotal'

        try:
            for future in as_completed(futures_map, timeout=config['overall_timeout']):
                check_name = futures_map[future]
                try:
                    threats = future.result()
                    if threats and isinstance(threats, list):
                        for threat in threats:
                            if threat not in self.results['threats_found']:
                                self.results['threats_found'].append(threat)
                except Exception as e:
                    logger.warning(f"[ThreatDetector] service '{check_name}' error: {e}")
                    self.results['details'].append(f'⚠️ خدمة {check_name} واجهت خطأ أثناء الفحص')
        except FuturesTimeout:
            logger.warning("[ThreatDetector] Overall scan timeout.")
            self.results['scan_failed'] = True
            self.results['details'].append('⚠️ انتهت مهلة فحص المصادر الخارجية')

        # Check if ALL requested services failed to produce a valid response
        expected_services_count = len(futures_map)
        successful_services = 0
        if self.results.get('vt_success'):
            successful_services += 1
        if self.results.get('gsb_success'):
            successful_services += 1

        if expected_services_count > 0 and successful_services == 0 and not self.results['threats_found']:
            self.results['scan_failed'] = True

        self._calculate_final_score()
        return self.results

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def _check_google_safe_browsing(self, url: str, timeout: float) -> list:
        """GSB Lookup."""
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
            payload = {
                "client": {"clientId": "safeclick", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            resp = requests.post(api_url, json=payload, timeout=timeout)
            if resp.status_code == 200:
                self.results['gsb_success'] = True
                try:
                    data = resp.json()
                    matches = data.get('matches', [])
                    return [{'type': 'google_safe', 'severity': 5, 'description': 'تم رصده كتهديد من قبل Google Safe Browsing'}] if matches else []
                except ValueError:
                    logger.error("[GSB] Invalid JSON response")
            else:
                logger.warning(f"[GSB] HTTP Error {resp.status_code}")
                self.results['details'].append(f"⚠️ Google Safe Browsing: استجابة غير متوقعة ({resp.status_code})")
        except Exception as e:
            logger.error(f"[GSB] Connection error: {e}")
            self.results['details'].append("⚠️ Google Safe Browsing: تعذر الاتصال بالخدمة")
        return []

    def _check_virustotal(self, url: str, request_timeout: float) -> list:
        """VT Lookup with budget-aware polling."""
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY, "accept": "application/json"}
        start_time = time.time()
        data = None

        try:
            # 1. Submit
            post_resp = None
            try:
                post_resp = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers, timeout=5.0)
            except Exception as e:
                logger.error(f"[VT] POST failed: {e}")

            if post_resp and post_resp.status_code == 429:
                logger.warning("[VT] Rate limit hit (HTTP 429)")
                self.results['details'].append("⚠️ VirusTotal: تم تجاوز حد الطلبات المسموح (Rate limit 429)")

            if post_resp and post_resp.status_code in (200, 202):
                try:
                    analysis_id = post_resp.json().get('data', {}).get('id')
                except ValueError:
                    analysis_id = None
                
                if analysis_id:
                    # 2. Poll (Check up to 3 times to prevent blocking server threads)
                    for _ in range(3):
                        if (time.time() - start_time) + 2.0 > request_timeout: break
                        time.sleep(1.5)
                        try:
                            poll_resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=5.0)
                            if poll_resp.status_code == 200:
                                poll_data = poll_resp.json()
                                if poll_data.get('data', {}).get('attributes', {}).get('status') == 'completed':
                                    data = poll_data
                                    break
                            elif poll_resp.status_code == 429:
                                logger.warning("[VT] Rate limit hit during polling")
                                break
                        except Exception as e:
                            logger.error(f"[VT] Poll error: {e}")

            # 3. Cache Fallback (check pre-existing analysis)
            if not data:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
                try:
                    get_resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5.0)
                    if get_resp.status_code == 200:
                        data = get_resp.json()
                    elif get_resp.status_code == 429:
                        logger.warning("[VT] Rate limit hit on GET fallback")
                        self.results['details'].append("⚠️ VirusTotal: تم تجاوز حد الطلبات (Rate limit 429)")
                except Exception as e:
                    logger.error(f"[VT] GET fallback error: {e}")

            if data:
                self.results['vt_success'] = True
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                if malicious > 0:
                    self.results['details'].append(f"⚠️ VirusTotal: {malicious} محرك رصد تهديداً ({total})")
                    return [{'type': 'virustotal', 'severity': 5, 'description': f'تم اكتشاف الرابط كملغم من {malicious} محرك في VirusTotal'}]
                elif suspicious > 0:
                    self.results['details'].append(f"⚠️ VirusTotal: {suspicious} محرك اشتبه بالرابط ({total})")
                    return [{'type': 'virustotal', 'severity': 3, 'description': f'اشتباه في الرابط من قبل {suspicious} محرك في VirusTotal'}]
                else:
                    self.results['details'].append(f"✅ VirusTotal: الرابط نظيف (أكده {stats.get('harmless', 0)} محرك)")
            else:
                if not any('VirusTotal' in d for d in self.results['details']):
                    self.results['details'].append("⚠️ VirusTotal: لم يتم استلام تقرير تحليل مكتمل")
        except Exception as e:
            logger.error(f"[VT] Error: {e}")
            self.results['details'].append("⚠️ VirusTotal: تعذر إكمال الاتصال")
        return []

    def _calculate_final_score(self) -> None:
        """Final decision based ONLY on verified threats or confirmed safe responses."""
        threats = self.results['threats_found']
        self.results['threats_count'] = len(threats)
        
        if self.results.get('scan_failed'):
            self.results['score'] = 50
            self.results['safe'] = None
            self.results['final_status'] = 'غير محدد'
            self.results['final_message'] = '⚠️ تعذر التحقق الكامل من المصادر الخارجية'
            if not self.results['details']:
                self.results['details'] = ['⚠️ تعذر الاتصال بمصادر الفحص الخارجية']
        elif not threats:
            vt_ok = self.results.get('vt_success', False)
            gsb_ok = self.results.get('gsb_success', False)

            if vt_ok and gsb_ok:
                # Both engines fully verified clean
                self.results['score'] = 100
                self.results['safe'] = True
                self.results['final_status'] = 'آمن'
                self.results['final_message'] = '✓ نتيجة الفحص: الرابط آمن (معتمد من Google Safe Browsing و VirusTotal)'
                if not self.results['details']:
                    self.results['details'] = ['✓ المصادر الخارجية لم تعثر على أي تهديدات']
            elif vt_ok and not gsb_ok:
                # VT confirmed clean (70+ security vendors)
                self.results['score'] = 100
                self.results['safe'] = True
                self.results['final_status'] = 'آمن'
                self.results['final_message'] = '✓ نتيجة الفحص: الرابط آمن وفق فحص VirusTotal'
            elif gsb_ok and not vt_ok:
                # GSB alone verified; VT hit rate limit (429) or timed out.
                # Defensive Depth: Do not grant blind 100% score to prevent Fail-Open under API exhaustion.
                self.results['score'] = 80
                self.results['safe'] = True
                self.results['final_status'] = 'فحص جزئي'
                self.results['final_message'] = '✓ الرابط يبدو آمناً وفق Google Safe Browsing (تعذر فحص VirusTotal لتجاوز كوتا الطلبات)'
            else:
                # Inconclusive (neither confirmed malicious nor confirmed clean)
                self.results['score'] = 50
                self.results['safe'] = None
                self.results['final_status'] = 'غير مؤكد'
                self.results['final_message'] = '⚠️ تعذر تأكيد سلامة الرابط من المصادر الخارجية'
        else:
            max_severity = max(t.get('severity', 0) for t in threats)
            if max_severity >= 5:
                self.results['score'] = 10
                self.results['safe'] = False
                self.results['final_status'] = 'خطير'
                self.results['final_message'] = '🔴 تحذير: هذا الرابط خطير جداً!'
            else:
                self.results['score'] = 45
                self.results['safe'] = None
                self.results['final_status'] = 'مشبوه'
                self.results['final_message'] = '⚠️ تنبيه: تم رصد مؤشرات مشبوهة'