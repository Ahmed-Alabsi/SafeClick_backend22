from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    DashboardStatsView, AdminMeView, ScanViewSet, DomainViewSet, 
    WhitelistViewSet, BlacklistViewSet, UserViewSet, ScanCacheViewSet, 
    ReportViewSet, AppRatingViewSet, ScanSourceResultViewSet
)

router = DefaultRouter()
router.register(r'scans', ScanViewSet, basename='admin-scans')
router.register(r'domains', DomainViewSet, basename='admin-domains')
router.register(r'whitelist', WhitelistViewSet, basename='admin-whitelist')
router.register(r'blacklist', BlacklistViewSet, basename='admin-blacklist')
router.register(r'users', UserViewSet, basename='admin-users')
router.register(r'cache', ScanCacheViewSet, basename='admin-cache')
router.register(r'reports', ReportViewSet, basename='admin-reports')
router.register(r'app-ratings', AppRatingViewSet, basename='admin-app-ratings')
router.register(r'source-results', ScanSourceResultViewSet, basename='admin-source-results')

urlpatterns = [
    path('stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    path('me/', AdminMeView.as_view(), name='dashboard-me'),
    path('', include(router.urls)),
]
