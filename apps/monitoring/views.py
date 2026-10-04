# apps/monitoring/views.py
"""
Monitoring API Views
────────────────────
Exposes engine health data to the admin frontend dashboard.

Endpoints:
  GET /api/monitoring/engines/           → all engines summary
  GET /api/monitoring/engines/<name>/    → single engine summary
  GET /api/monitoring/logs/              → recent raw health logs (paginated)
"""

import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser
from rest_framework.pagination import PageNumberPagination
from rest_framework import serializers
from django.utils import timezone
from datetime import timedelta

from .models import EngineHealthLog
from .services import EngineHealthService

logger = logging.getLogger(__name__)


# ── Serializer ───────────────────────────────────────────────────────────────

class EngineHealthLogSerializer(serializers.ModelSerializer):
    engine_label = serializers.CharField(
        source='get_engine_name_display', read_only=True)
    status_label = serializers.CharField(
        source='get_status_display', read_only=True)

    class Meta:
        model = EngineHealthLog
        fields = [
            'id', 'engine_name', 'engine_label',
            'status', 'status_label',
            'latency_ms', 'error_message',
            'scan_url', 'checked_at',
        ]


# ── Pagination ───────────────────────────────────────────────────────────────

class HealthLogPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 200


# ── Views ─────────────────────────────────────────────────────────────────────

class EnginesSummaryView(APIView):
    """
    GET /api/monitoring/engines/
    Returns a health summary for ALL engines (last 100 calls each).
    Used by the admin dashboard overview widget.
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        last_n = int(request.query_params.get('last_n', 100))
        summaries = EngineHealthService.get_all_engines_summary(last_n=last_n)

        # Add a human-readable label to each summary
        choices_map = dict(EngineHealthLog.ENGINE_CHOICES)
        for s in summaries:
            s['label'] = choices_map.get(s.get('engine', ''), s.get('engine', ''))

        return Response({
            'engines': summaries,
            'generated_at': timezone.now().isoformat(),
        })


class EngineSummaryDetailView(APIView):
    """
    GET /api/monitoring/engines/<engine_name>/
    Returns health summary for a specific engine.
    """
    permission_classes = [IsAdminUser]

    def get(self, request, engine_name: str):
        valid_keys = {k for k, _ in EngineHealthLog.ENGINE_CHOICES}
        if engine_name not in valid_keys:
            return Response(
                {'error': f'Unknown engine: {engine_name}'},
                status=400
            )

        last_n = int(request.query_params.get('last_n', 100))
        summary = EngineHealthService.get_engine_summary(engine_name, last_n=last_n)

        # Add recent logs for sparkline data (last 20 calls)
        recent_logs = (
            EngineHealthLog.objects
            .filter(engine_name=engine_name)
            .order_by('-checked_at')[:20]
        )
        summary['recent_logs'] = EngineHealthLogSerializer(
            recent_logs, many=True).data

        choices_map = dict(EngineHealthLog.ENGINE_CHOICES)
        summary['label'] = choices_map.get(engine_name, engine_name)

        return Response(summary)


class EngineHealthLogsView(APIView):
    """
    GET /api/monitoring/logs/
    Returns paginated raw engine health log records.

    Query params:
      engine   → filter by engine_name
      status   → filter by status
      hours    → look back N hours (default 24)
      page     → page number
      page_size→ results per page (max 200)
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        hours_param = request.query_params.get('hours')
        engine = request.query_params.get('engine')
        status = request.query_params.get('status')

        if hours_param:
            since = timezone.now() - timedelta(hours=int(hours_param))
            qs = EngineHealthLog.objects.filter(checked_at__gte=since).order_by('-checked_at')
        else:
            qs = EngineHealthLog.objects.all().order_by('-checked_at')

        if engine:
            qs = qs.filter(engine_name=engine)
        if status:
            qs = qs.filter(status=status)

        paginator = HealthLogPagination()
        page = paginator.paginate_queryset(qs, request)
        serializer = EngineHealthLogSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class EngineStatsOverviewView(APIView):
    """
    GET /api/monitoring/overview/
    High-level stats: total scans logged, error count, avg latency per engine,
    and which engines have been degraded in the last hour.
    Used by the top-of-dashboard alert banner.
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        from django.db.models import Avg, Count, Q

        hours = int(request.query_params.get('hours', 1))
        since = timezone.now() - timedelta(hours=hours)

        qs = EngineHealthLog.objects.filter(checked_at__gte=since)

        total = qs.count()
        error_count = qs.filter(status__in=['error', 'timeout']).count()
        degraded_engines = list(
            qs.filter(status='degraded')
            .values_list('engine_name', flat=True)
            .distinct()
        )
        avg_latency = qs.aggregate(avg=Avg('latency_ms'))['avg'] or 0.0

        # Which engines have NOT logged anything in the last hour?
        # (indicates they might be offline / never integrated)
        all_engine_keys = {k for k, _ in EngineHealthLog.ENGINE_CHOICES}
        active_engines  = set(qs.values_list('engine_name', flat=True).distinct())
        silent_engines  = sorted(all_engine_keys - active_engines)

        choices_map = dict(EngineHealthLog.ENGINE_CHOICES)

        return Response({
            'window_hours':      hours,
            'total_log_entries': total,
            'error_count':       error_count,
            'error_rate_pct':    round((error_count / total * 100) if total else 0, 1),
            'avg_latency_ms':    round(avg_latency, 2),
            'degraded_engines':  [choices_map.get(e, e) for e in degraded_engines],
            'silent_engines':    [
                {'key': e, 'label': choices_map.get(e, e)} for e in silent_engines
            ],
            'generated_at':      timezone.now().isoformat(),
        })
