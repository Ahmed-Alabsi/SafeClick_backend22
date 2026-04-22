# apps/monitoring/urls.py
from django.urls import path
from .views import (
    EnginesSummaryView,
    EngineSummaryDetailView,
    EngineHealthLogsView,
    EngineStatsOverviewView,
)

urlpatterns = [
    # Overview banner stats (errors, silent engines, avg latency)
    path('overview/',                   EngineStatsOverviewView.as_view(),  name='monitoring-overview'),

    # All engines summary
    path('engines/',                    EnginesSummaryView.as_view(),       name='monitoring-engines'),

    # Single engine detail + sparkline
    path('engines/<str:engine_name>/',  EngineSummaryDetailView.as_view(),  name='monitoring-engine-detail'),

    # Raw paginated logs
    path('logs/',                       EngineHealthLogsView.as_view(),     name='monitoring-logs'),
]
