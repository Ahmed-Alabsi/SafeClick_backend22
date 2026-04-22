from rest_framework import viewsets, permissions, views, status, filters, mixins
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Q

from apps.scans.models import Scan, WhitelistEntry, Blacklist, ScanCache
from apps.domains.models import Domain
from apps.accounts.models import User
from apps.reports.models import Report
from apps.monitoring.models import AuditLog

from .serializers import (
    DashboardScanSerializer, ScanDetailSerializer, DashboardDomainSerializer,
    WhitelistSerializer, BlacklistReadSerializer, BlacklistCreateSerializer,
    UserSerializer, ScanCacheSerializer, ReportSerializer
)


class IsAdminUser(permissions.BasePermission):
    """Only allow superusers to access admin API."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_superuser)


class AdminMeView(views.APIView):
    """Return current admin user profile data."""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get(self, request):
        return Response({
            'name': request.user.name,
            'email': request.user.email,
            'is_superuser': request.user.is_superuser,
            'is_staff': request.user.is_staff,
        })


class DashboardStatsView(views.APIView):
    """Aggregated dashboard statistics with optimized queries."""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get(self, request):
        today = timezone.now()
        seven_days_ago = today - timedelta(days=7)
        fourteen_days_ago = today - timedelta(days=14)

        # Single aggregated query for all time totals
        scan_stats = Scan.objects.aggregate(
            total_scans=Count('id'),
            safe_scans=Count('id', filter=Q(safe=True)),
            threat_scans=Count('id', filter=Q(safe=False)),
            suspicious=Count('id', filter=Q(final_verdict='suspicious')),
        )

        last_7_stats = Scan.objects.filter(created_at__gte=seven_days_ago).aggregate(
            total_scans=Count('id'), safe_scans=Count('id', filter=Q(safe=True)),
            threat_scans=Count('id', filter=Q(safe=False)), suspicious=Count('id', filter=Q(final_verdict='suspicious')),
        )
        prev_7_stats = Scan.objects.filter(created_at__gte=fourteen_days_ago, created_at__lt=seven_days_ago).aggregate(
            total_scans=Count('id'), safe_scans=Count('id', filter=Q(safe=True)),
            threat_scans=Count('id', filter=Q(safe=False)), suspicious=Count('id', filter=Q(final_verdict='suspicious')),
        )

        def calc_trend(curr, prev):
            if not prev: return f"+{curr * 100}%" if curr else "+0%"
            change = ((curr - prev) / prev) * 100
            return f"+{change:.1f}%" if change > 0 else f"{change:.1f}%"

        trend_percentages = {
            'total_scans': calc_trend(last_7_stats['total_scans'], prev_7_stats['total_scans']),
            'safe_scans': calc_trend(last_7_stats['safe_scans'], prev_7_stats['safe_scans']),
            'threat_scans': calc_trend(last_7_stats['threat_scans'], prev_7_stats['threat_scans']),
            'suspicious': calc_trend(last_7_stats['suspicious'], prev_7_stats['suspicious']),
            'total_users': calc_trend(
                User.objects.filter(created_at__gte=seven_days_ago).count(),
                User.objects.filter(created_at__gte=fourteen_days_ago, created_at__lt=seven_days_ago).count()
            ),
            'total_blacklisted': calc_trend(
                Blacklist.objects.filter(added_at__gte=seven_days_ago).count(),
                Blacklist.objects.filter(added_at__gte=fourteen_days_ago, added_at__lt=seven_days_ago).count()
            )
        }

        total_users = User.objects.count()
        total_blacklisted = Blacklist.objects.filter(is_active=True).count()

        # Last 7 days trend with BOTH scans and threats per day for the chart
        trend_data = (
            Scan.objects.filter(created_at__gte=seven_days_ago)
            .values('created_at__date')
            .annotate(
                count=Count('id'),
                threat_count=Count('id', filter=Q(safe=False)),
            )
            .order_by('created_at__date')
        )

        trends = [{'date': d['created_at__date'].strftime('%Y-%m-%d'), 'scans': d['count'], 'threats': d['threat_count']} for d in trend_data]

        recent_threats = Scan.objects.filter(safe=False).select_related('user').order_by('-created_at')[:5]
        threats_serializer = DashboardScanSerializer(recent_threats, many=True)

        return Response({
            'stats': {
                'total_scans': scan_stats['total_scans'],
                'safe_scans': scan_stats['safe_scans'],
                'threat_scans': scan_stats['threat_scans'],
                'suspicious': scan_stats['suspicious'],
                'total_users': total_users,
                'total_blacklisted': total_blacklisted,
            },
            'trend_percentages': trend_percentages,
            'trends': trends,
            'recent_threats': threats_serializer.data
        })


class ScanViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = DashboardScanSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['url', 'domain_name', 'final_verdict']
    ordering_fields = ['created_at', 'risk_score']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return ScanDetailSerializer
        return DashboardScanSerializer

    def get_queryset(self):
        queryset = Scan.objects.select_related('user').all().order_by('-created_at')
        
        verdict = self.request.query_params.get('verdict')
        if verdict:
            queryset = queryset.filter(final_verdict=verdict)
            
        scan_level = self.request.query_params.get('scan_level')
        if scan_level:
            queryset = queryset.filter(scan_level=scan_level)
            
        date_from = self.request.query_params.get('date_from')
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
            
        date_to = self.request.query_params.get('date_to')
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
            
        return queryset




class DomainViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = DashboardDomainSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['domain']
    ordering_fields = ['last_checked', 'threat_ratio', 'total_scans']

    def get_queryset(self):
        queryset = Domain.objects.all().order_by('-last_checked')
        min_risk = self.request.query_params.get('min_risk')
        if min_risk is not None:
            try:
                risk_val = float(min_risk)
                # min_risk is sent as a percentage (e.g., 50), threat_ratio is 0.0 to 1.0
                ratio_val = risk_val / 100.0
                queryset = queryset.filter(threat_ratio__gte=ratio_val)
            except ValueError:
                pass
        return queryset


class WhitelistViewSet(mixins.CreateModelMixin,
                       mixins.DestroyModelMixin,
                       mixins.ListModelMixin,
                       mixins.RetrieveModelMixin,
                       viewsets.GenericViewSet):
    """Whitelist: List, Create, Delete only (no PUT/PATCH)."""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    queryset = WhitelistEntry.objects.select_related('added_by').all().order_by('-created_at')
    serializer_class = WhitelistSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['domain']
    ordering_fields = ['created_at']

    def perform_create(self, serializer):
        entry = serializer.save(added_by=self.request.user)
        AuditLog.objects.create(
            user=self.request.user,
            action='create',
            resource_type='Whitelist',
            resource_id=entry.domain,
            details=f"Added domain to whitelist: {entry.domain}",
            ip_address=self.request.META.get('REMOTE_ADDR')
        )

    def perform_destroy(self, instance):
        AuditLog.objects.create(
            user=self.request.user,
            action='delete',
            resource_type='Whitelist',
            resource_id=instance.domain,
            details=f"Removed domain from whitelist: {instance.domain}",
            ip_address=self.request.META.get('REMOTE_ADDR')
        )
        instance.delete()


class BlacklistViewSet(mixins.CreateModelMixin,
                       mixins.DestroyModelMixin,
                       mixins.ListModelMixin,
                       mixins.RetrieveModelMixin,
                       viewsets.GenericViewSet):
    """Blacklist: List, Create, Delete only (no PUT/PATCH)."""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    queryset = Blacklist.objects.all().order_by('-added_at')
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['domain', 'link', 'threat_type']
    ordering_fields = ['added_at']

    def get_serializer_class(self):
        if self.action == 'create':
            return BlacklistCreateSerializer
        return BlacklistReadSerializer

    def perform_create(self, serializer):
        entry = serializer.save()
        val = entry.domain or entry.link or str(entry.id)
        AuditLog.objects.create(
            user=self.request.user,
            action='create',
            resource_type='Blacklist',
            resource_id=val,
            details=f"Added to blacklist: {val} (Severity: {entry.severity})",
            ip_address=self.request.META.get('REMOTE_ADDR')
        )

    def perform_destroy(self, instance):
        val = instance.domain or instance.link or str(instance.id)
        AuditLog.objects.create(
            user=self.request.user,
            action='delete',
            resource_type='Blacklist',
            resource_id=val,
            details=f"Removed from blacklist: {val}",
            ip_address=self.request.META.get('REMOTE_ADDR')
        )
        instance.delete()


from rest_framework.decorators import action

class UserViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = UserSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['email', 'name']
    ordering_fields = ['created_at', 'scanned_links', 'detected_threats']

    def get_queryset(self):
        queryset = User.objects.all().order_by('-created_at')
        role = self.request.query_params.get('role')
        status = self.request.query_params.get('status')
        
        if role == 'admin':
            queryset = queryset.filter(is_staff=True)
        elif role == 'user':
            queryset = queryset.filter(is_staff=False)
            
        if status == 'active':
            queryset = queryset.filter(is_active=True)
        elif status == 'inactive':
            queryset = queryset.filter(is_active=False)
            
        return queryset

    @action(detail=True, methods=['post'])
    def toggle_status(self, request, pk=None):
        user = self.get_object()
        # Prevent admin from deactivating themselves
        if user == request.user:
            return Response({'error': 'Cannot deactivate your own account'}, status=400)
            
        user.is_active = not user.is_active
        user.save()
        
        AuditLog.objects.create(
            user=self.request.user,
            action='update',
            resource_type='User',
            resource_id=str(user.id),
            details=f"Changed user {user.email} active status to {user.is_active}",
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        return Response({'status': 'success', 'is_active': user.is_active})


class ScanCacheViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    queryset = ScanCache.objects.all().order_by('-scanned_at')
    serializer_class = ScanCacheSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['url', 'result']
    ordering_fields = ['scanned_at']


class ReportViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    queryset = Report.objects.select_related('user').all().order_by('-created_at')
    serializer_class = ReportSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['link', 'user__email', 'category']
    ordering_fields = ['created_at']
