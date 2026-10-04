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
    """التحقق من صحة وصيغة المعرف الخاص بالزائر (يدعم JWT أو Header) مع التحقق من وجود الجلسة ونشاطها"""
    from apps.accounts.models import GuestSession
    from django.utils import timezone

    # 1. محاولة استخراج الهوية من JWT (الطريقة الأكثر أماناً)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        guest_secret = getattr(settings, 'GUEST_JWT_SECRET', settings.SECRET_KEY + '-guest-ns')
        try:
            payload = jwt.decode(
                token,
                guest_secret,
                algorithms=['HS256'],
                audience='safeclick-client',
                issuer='safeclick-backend',
            )
            if payload.get('is_guest'):
                guest_uuid = UUID(payload.get('guest_id'))
                if GuestSession.objects.filter(id=guest_uuid, is_active=True, expires_at__gt=timezone.now()).exists():
                    return guest_uuid
        except Exception:
            pass # ليس توكن زائر صالح، قد يكون توكن مستخدم عادي

    # 2. محاولة استخراج الهوية من Header (للتوافق مع التحقق من قاعدة البيانات)
    guest_id = request.headers.get("X-Guest-ID")
    if not guest_id:
        return None
    try:
        guest_uuid = UUID(guest_id)
        if GuestSession.objects.filter(id=guest_uuid, is_active=True, expires_at__gt=timezone.now()).exists():
            return guest_uuid
        return None
    except (ValueError, TypeError):
        return None

class ScanLinkView(APIView):
    """فحص رابط جديد — Phase 5/Guest Support: Authentication Optional but with stricter rate limiting for guests."""
    from rest_framework.throttling import UserRateThrottle

    class ScanRateThrottle(UserRateThrottle):
        rate = '20/min'

    permission_classes = [AllowAny]
    # SECURITY NOTE (SEC-H06): Authentication is handled MANUALLY inside post() because
    # this endpoint supports three distinct auth paths: SimpleJWT for registered users,
    # custom PyJWT with GUEST_JWT_SECRET for guests, and rate-limited guest creation.
    # DRF's default SimpleJWT would reject valid guest tokens with 401 Invalid Token.
    authentication_classes = []
    throttle_classes = [ScanRateThrottle]

    def post(self, request):
        # 1. Manual User Authentication (for logged-in users)
        user = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            from rest_framework_simplejwt.authentication import JWTAuthentication
            try:
                auth = JWTAuthentication().authenticate(request)
                if auth:
                    user = auth[0]
                    request.user = user # Set request.user for consistency
            except Exception:
                pass # Might be a guest token, handled below

        # 2. Guest Identity Check
        guest_id = get_valid_guest_id(request)
        is_authenticated = user is not None and user.is_authenticated

        # ── Identity & Quota Guardrail ──
        if not is_authenticated:
            if not guest_id:
                logger.warning("[SCAN] محاولة فحص بدون هوية (بدون Token أو Guest-ID). تم الرفض.")
                return Response({
                    'success': False,
                    'message': 'يجب توفير معرف الزائر (Guest ID) أو تسجيل الدخول لاستخدام خدمة الفحص.',
                    'code': 'identity_required'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Atomic quota reservation using row-level locking (Zero race conditions)
            from apps.accounts.models import GuestSession
            FREE_GUEST_SCANS_LIMIT = getattr(settings, 'FREE_GUEST_SCANS_LIMIT', 3)
            allowed, used_count = GuestSession.check_and_increment_quota(guest_id, limit=FREE_GUEST_SCANS_LIMIT)
            if not allowed:
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
                # Structured debug logging in development mode
                if settings.DEBUG:
                    logger.debug(
                        "Scan completed: %s | level: %s | duration: %.2fs | safe: %s | sources: %d",
                        link,
                        scan_level,
                        duration,
                        service_result.get('safe'),
                        len(service_result.get('sources', []))
                    )

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
                if not is_authenticated and guest_id:
                    GuestSession.rollback_quota(guest_id)
                logger.error(f"خطأ في الفحص: {str(e)}")
                return Response({
                    'success': False,
                    'message': 'حدث خطأ أثناء الفحص'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        else:
            logger.warning(f"[SCAN] رابط غير صالح أو فشل التحقق: {serializer.errors}")
            return Response({
                'success': False,
                'message': 'رابط غير صالح',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)




class ScanHistoryView(APIView):
    """عرض سجل الفحوصات — Phase 3: optimized query with secure identity resolution"""
    permission_classes = [AllowAny]
    authentication_classes = []  # Disable automatic JWT rejection to support guests seamlessly

    def get(self, request):
        # 1. المصادقة اليدوية للمستخدمين المسجلين (Manual JWT Authentication)
        user = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            from rest_framework_simplejwt.authentication import JWTAuthentication
            try:
                auth = JWTAuthentication().authenticate(request)
                if auth:
                    user = auth[0]
            except Exception:
                pass

        guest_id = get_valid_guest_id(request)
        
        # تصفية حسب المستخدم المسجل أو المعرف الفريد للزائر
        if user and user.is_authenticated:
            query = Q(user=user)
        elif request.user and request.user.is_authenticated:
            query = Q(user=request.user)
        elif guest_id:
            query = Q(guest_id=guest_id, user__isnull=True)
        else:
            return Response({
                'success': True,
                'history': [],
                'count': 0,
                'message': 'يرجى تسجيل الدخول أو توفير معرف الزائر'
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
