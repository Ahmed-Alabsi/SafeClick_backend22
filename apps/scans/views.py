# apps/scans/views.py
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Scan
from .serializers import ScanResultSerializer, ScanLinkSerializer
from services.url_scan_service import scan_url
import logging

from django.db.models import Q
from uuid import UUID
from django.conf import settings
import jwt


logger = logging.getLogger(__name__)

def get_valid_guest_id(request):
    """التحقق من صحة وصيغة المعرف الخاص بالزائر (يدعم JWT أو Header)"""
    # 1. محاولة استخراج الهوية من JWT (الطريقة الجديدة والأكثر أماناً)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            if payload.get('is_guest'):
                return UUID(payload.get('guest_id'))
        except Exception:
            pass # ليس توكن زائر صالح، قد يكون توكن مستخدم عادي

    # 2. محاولة استخراج الهوية من Header (الطريقة القديمة - للتوافق)
    guest_id = request.headers.get("X-Guest-ID")
    if not guest_id:
        return None
    try:
        return UUID(guest_id)
    except (ValueError, TypeError):
        return None

class ScanLinkView(APIView):
    """فحص رابط جديد — Phase 5/Guest Support: Authentication Optional but with stricter rate limiting for guests."""
    from rest_framework.throttling import UserRateThrottle

    class ScanRateThrottle(UserRateThrottle):
        rate = '20/min'

    permission_classes = [AllowAny]
    throttle_classes = [ScanRateThrottle]

    def post(self, request):
        guest_id = get_valid_guest_id(request)
        is_authenticated = request.user.is_authenticated

        # ── Identity & Quota Guardrail ──
        if not is_authenticated:
            if not guest_id:
                logger.warning("[SCAN] محاولة فحص بدون هوية (بدون Token أو Guest-ID). تم الرفض.")
                return Response({
                    'success': False,
                    'message': 'يجب توفير معرف الزائر (Guest ID) أو تسجيل الدخول لاستخدام خدمة الفحص.',
                    'code': 'identity_required'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Check guest quota
            FREE_GUEST_SCANS_LIMIT = getattr(settings, 'FREE_GUEST_SCANS_LIMIT', 3)
            guest_scan_count = Scan.objects.filter(guest_id=guest_id, user__isnull=True).count()
            if guest_scan_count >= FREE_GUEST_SCANS_LIMIT:
                logger.warning(f"[SCAN] الزائر {guest_id} تجاوز الحد المجاني ({FREE_GUEST_SCANS_LIMIT}). تم الرفض.")
                return Response({
                    'success': False,
                    'message': f'لقد استنفدت عدد الفحوصات المجانية المتاحة لك كزائر ({FREE_GUEST_SCANS_LIMIT} فحوصات). يرجى إنشاء حساب أو تسجيل الدخول لمتابعة الفحص مجاناً.',
                    'code': 'guest_limit_reached'
                }, status=status.HTTP_403_FORBIDDEN)

        user_identifier = request.user.email if is_authenticated else f"Guest:{guest_id}"
        logger.info("[SCAN] طلب فحص رابط من: %s", user_identifier)
        
        serializer = ScanLinkSerializer(data=request.data)
        
        if serializer.is_valid():
            link = serializer.validated_data['link']
            scan_level = serializer.validated_data.get('scan_level', 'deep')
            ignore_cache = request.data.get('ignore_cache', False) or request.data.get('force_scan', False)
            
            logger.info("[SCAN] الرابط: %s | مستوى الفحص: %s | تجاوز الكاش: %s", link, scan_level, ignore_cache)
            
            is_guest = not request.user.is_authenticated
            # Note: Stricter rate limiting is handled by throttle_classes, not by scan counts anymore.


            import time
            start_time = time.time()

            try:
                # If the user is authenticated, pass the user object, otherwise pass None
                user = request.user if request.user.is_authenticated else None
                service_result = scan_url(
                    url=link, 
                    user=user, 
                    scan_level=scan_level, 
                    guest_id=guest_id,
                    ignore_cache=ignore_cache
                )
                
                duration = time.time() - start_time
                meta = service_result.get('meta', {})
                logger.info({
                    "event": "scan_completed",
                    "url": link,
                    "scan_level": scan_level,
                    "duration": round(duration, 2),
                    "status": service_result.get('result'),
                    "cache_hit": meta.get('cache_hit', False),
                    "ttl": meta.get('ttl', 0)
                })
                # -- Detailed Terminal Output --
                def safe_print(msg):
                    try:
                        print(msg)
                    except UnicodeEncodeError:
                        print(msg.encode('ascii', 'replace').decode('ascii'))

                safe_print("\n" + "="*60)
                safe_print(f"🔍 تفاصيل الفحص للرابط: {link}")
                safe_print(f"📊 مستوى الفحص: {scan_level} | ⏱️ المدة: {round(duration, 2)}s")
                safe_print(f"🛡️ الحالة النهائية: {'✅ آمن' if service_result.get('safe') else '🔴 خطر/مشبوه'}")
                safe_print("-"*60)
                
                sources = service_result.get('sources', [])
                if not sources:
                    safe_print("⚠️ لم يتم استخدام أي محركات فحص (قد يكون الرابط غير صالح).")
                
                for idx, src in enumerate(sources, 1):
                    src_type = src.get('source_type', 'Unknown').upper()
                    verdict = src.get('verdict', 'Unknown')
                    r_score = src.get('risk_score', 0)
                    safe_print(f"[{idx}] محرك ({src_type}) | النتيجة: {verdict} | مستوى الخطر: {r_score}%")
                    
                    # Print raw data if available (e.g. from domain_analysis)
                    raw_data = src.get('raw_data', {})
                    if raw_data:
                        engines = raw_data.get('engines', {})
                        if engines:
                            safe_print("    -- المحركات الفرعية --")
                            for eng_name, eng_res in engines.items():
                                status_val = eng_res.get('status', 'unknown')
                                if status_val == 'ok':
                                    details = eng_res.get('details', {})
                                    if eng_name == 'ml_classifier':
                                        safe_print(f"      🧠 ML Engine (XGBoost): {details.get('ml_verdict')} (Score: {details.get('ml_score')})")
                                    elif eng_name == 'url_features':
                                        safe_print(f"      🔗 URL Analysis: Risk Score {details.get('risk_score', 0)}")
                                    elif eng_name == 'typosquatting':
                                        if details.get('is_typosquatting'):
                                            brand = details.get('target_brand', details.get('target_domain', '?'))
                                            method = details.get('method', 'detection')
                                            safe_print(f"      🚨 Typosquatting: Detected → {brand} ({method})")
                                        else:
                                            safe_print(f"      📝 Typosquatting: Clean")
                                    elif eng_name == 'phishing_patterns':
                                        safe_print(f"      🎣 Phishing Patterns: {len(details.get('keywords', []))} suspicious matches")
                                    elif eng_name == 'threat_intelligence':
                                        safe_print(f"      🌍 Threat Intel (OpenPhish): {'Listed' if details.get('blacklisted') else 'Clean'}")
                                    elif eng_name == 'dns':
                                        resolves = details.get('resolves', False)
                                        res_status = details.get('resolution_status', 'unknown')
                                        if resolves:
                                            safe_print(f"      ✅ dns: OK (Resolved)")
                                        else:
                                            safe_print(f"      ❌ dns: FAILED ({res_status})")
                                    elif eng_name == 'ssl':
                                        errors = details.get('errors', [])
                                        has_ssl = details.get('has_ssl', False)
                                        if has_ssl and not errors:
                                            safe_print(f"      🔒 ssl: Valid")
                                        elif has_ssl and details.get('is_expired'):
                                            safe_print(f"      ⚠️ ssl: Expired certificate")
                                        elif has_ssl and details.get('is_self_signed'):
                                            safe_print(f"      ⚠️ ssl: Self-signed certificate")
                                        elif not has_ssl:
                                            has_net_err = any(k in str(errors).lower() for k in ['timeout','refused','reset','unreachable','getaddrinfo'])
                                            if has_net_err:
                                                safe_print(f"      ✅ ssl: OK (network unreachable, not penalized)")
                                            else:
                                                safe_print(f"      ⚠️ ssl: No certificate")
                                        else:
                                            safe_print(f"      ✅ ssl: OK")
                                    elif eng_name == 'domain_age':
                                        age_days = details.get('age_days')
                                        if age_days is not None:
                                            if age_days < 30:
                                                safe_print(f"      ⚠️ domain_age: New domain ({age_days} days)")
                                            else:
                                                safe_print(f"      ✅ domain_age: OK ({age_days} days)")
                                        else:
                                            safe_print(f"      ✅ domain_age: OK")
                                    elif eng_name == 'homoglyph':
                                        h_details = details if isinstance(details, dict) else {}
                                        if h_details.get('confusable') or h_details.get('punycode') or h_details.get('latin_tricks'):
                                            safe_print(f"      🚨 homoglyph: Detected ({', '.join(h_details.get('details', []))})")
                                        else:
                                            safe_print(f"      ✅ homoglyph: OK")
                                    elif eng_name in ('fast_path', 'trusted_source'):
                                        safe_print(f"      ⚡ {eng_name}: Whitelisted")
                                    elif eng_name == 'url_unshortener':
                                        was_short = details.get('was_shortened', False)
                                        if was_short:
                                            final = details.get('final_url', '?')
                                            safe_print(f"      🔗 url_unshortener: Resolved → {final}")
                                        else:
                                            safe_print(f"      ✅ url_unshortener: OK")
                                    elif eng_name == 'open_redirect':
                                        if details.get('is_open_redirect'):
                                            safe_print(f"      🚨 open_redirect: {details.get('wrapper_domain')} → {details.get('target_domain')}")
                                        else:
                                            safe_print(f"      ✅ open_redirect: OK")
                                    else:
                                        safe_print(f"      ✅ {eng_name}: OK")
                                elif status_val == 'skipped':
                                    safe_print(f"      ⏭️ {eng_name}: Skipped")
                                else:
                                    safe_print(f"      ❌ {eng_name}: Failed ({eng_res.get('error', 'unknown')})")
                safe_print("="*60 + "\n")

                # Unified Model Alignment for Flutter ScanResult.fromJson
                # Convert Risk Score to Safety Score (100 = 100% Safe, 0 = 100% Dangerous)
                risk_score = service_result.get('risk_score', 0)
                safety_score = 100 - risk_score
                
                response_data = {
                    'id': service_result.get('id') or f"scan_{int(time.time())}",
                    'link': service_result.get('url'),
                    'safe': service_result.get('safe'),
                    'score': safety_score,
                    'message': service_result.get('final_message') or service_result.get('reason'),
                    'details': service_result.get('details') or service_result.get('detailed_report'),
                    'timestamp': service_result.get('scanned_at'),
                    'domain': service_result.get('domain'),
                    
                    # Telemetry (camelCase for Flutter)
                    'ipAddress': service_result.get('ip_address'),
                    'responseTime': service_result.get('response_time'),
                    'threats_count': service_result.get('threats_count', 0),
                    
                    # Cache / Rate Limit Visibility
                    'meta': service_result.get('meta', {}),
                    
                    # Legacy fallback
                    'final_status': service_result.get('final_status'),
                }
                
                return Response({
                    'success': True,
                    'result': response_data
                })
                
            except Exception as e:
                logger.error(f"خطأ في الفحص: {str(e)}")
                return Response({
                    'success': False,
                    'message': 'حدث خطأ أثناء الفحص'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class ScanHistoryView(APIView):
    """عرض سجل الفحوصات — Phase 3: optimized query"""
    permission_classes = [AllowAny]

    def get(self, request):
        guest_id = get_valid_guest_id(request)
        
        # تصفية حسب المستخدم المسجل أو المعرف الفريد للزائر
        if request.user.is_authenticated:
            query = Q(user=request.user)
        elif guest_id:
            query = Q(guest_id=guest_id, user__isnull=True)
        else:
            return Response({
                'success': True,
                'history': [],
                'message': 'No identity found (User or Guest ID)'
            })

        scans = (
            Scan.objects
            .filter(query)
            .filter(deleted_at__isnull=True)
            .only('id', 'url', 'result', 'safe', 'risk_score', 'created_at', 'domain', 'threats_count')
            .order_by('-created_at')[:50]
        )
        serializer = ScanResultSerializer(scans, many=True)
        data = serializer.data
        return Response({
            'success': True,
            'history': data,
            'count': len(data),
        })

class DeleteScanSoftView(APIView):
    """حذف فحص من السجل (Soft Delete)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        from django.shortcuts import get_object_or_404
        from django.utils import timezone
        scan = get_object_or_404(Scan, pk=pk, user=request.user)
        scan.deleted_at = timezone.now()
        scan.save()
        
        return Response({
            'success': True,
            'message': 'تم حذف الفحص من السجل بنجاح'
        })

class DeleteAllScansSoftView(APIView):
    """حذف جميع الفحوصات (Soft Delete)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        from django.utils import timezone
        count = Scan.objects.filter(
            user=request.user, 
            deleted_at__isnull=True
        ).update(deleted_at=timezone.now())
        
        return Response({
            'success': True,
            'message': f'تم حذف {count} فحص من السجل بنجاح'
        })

class RestoreScanSoftView(APIView):
    """استعادة فحص محذوف (Undo Soft Delete)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        from django.shortcuts import get_object_or_404
        scan = get_object_or_404(Scan, pk=pk, user=request.user)
        
        if scan.deleted_at is None:
            return Response({
                'success': False,
                'message': 'الفحص غير محذوف'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        scan.deleted_at = None
        scan.save(update_fields=['deleted_at'])
        
        return Response({
            'success': True,
            'message': 'تم استعادة الفحص بنجاح'
        })

class RestoreScansBulkView(APIView):
    """استعادة قائمة من الفحوصات المحذوفة مؤقتاً (Undo Delete Bulk)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        scan_ids = request.data.get('scan_ids', [])
        if not scan_ids:
            return Response({
                'success': False,
                'message': 'يجب تقديم قائمة معرفات الفحوصات استعادتها'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        count = Scan.objects.filter(
            user=request.user, 
            id__in=scan_ids,
            deleted_at__isnull=False
        ).update(deleted_at=None)
        
        return Response({
            'success': True,
            'message': f'تم استعادة {count} فحص بنجاح',
            'restored_count': count
        })
