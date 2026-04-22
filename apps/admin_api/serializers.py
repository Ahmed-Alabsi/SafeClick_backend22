from rest_framework import serializers
from apps.scans.models import Scan, ScanSourceResult, WhitelistEntry, Blacklist, ScanCache
from apps.domains.models import Domain
from apps.accounts.models import User
from apps.reports.models import Report


class DashboardScanSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True, default='مستخدم غير معروف')

    class Meta:
        model = Scan
        fields = ['id', 'url', 'domain_name', 'final_verdict', 'safety_score', 'risk_score', 'safe', 'created_at', 'user_email', 'scan_level']


class ScanSourceResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanSourceResult
        fields = ['source_type', 'verdict', 'risk_score', 'confidence', 'source_weight', 'latency_ms']


class ScanDetailSerializer(DashboardScanSerializer):
    source_results = ScanSourceResultSerializer(many=True, read_only=True)
    
    class Meta(DashboardScanSerializer.Meta):
        fields = DashboardScanSerializer.Meta.fields + ['ip_address', 'reason', 'scan_scenario', 'source_results']


class DashboardDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        fields = ['id', 'domain', 'total_scans', 'threat_detections', 'threat_ratio', 'safety_ratio', 'has_ssl', 'age_days']


class WhitelistSerializer(serializers.ModelSerializer):
    added_by_email = serializers.CharField(source='added_by.email', read_only=True, default='')

    class Meta:
        model = WhitelistEntry
        fields = ['id', 'domain', 'source', 'reason', 'is_active', 'notes', 'created_at', 'updated_at', 'expires_at', 'added_by_email']
        read_only_fields = ['id', 'created_at', 'updated_at', 'added_by_email']


class BlacklistCreateSerializer(serializers.Serializer):
    """
    Custom serializer to bridge the frontend form fields to the Blacklist model.
    Frontend sends: { type, value, severity: 'high'|'critical', reason }
    Backend model expects: { link, domain, threat_type, severity: int, description }
    """
    type = serializers.ChoiceField(choices=['domain', 'url', 'ip'], default='domain')
    value = serializers.CharField(max_length=2000)
    severity = serializers.ChoiceField(choices=['high', 'critical'], default='high')
    reason = serializers.CharField(required=False, allow_blank=True, default='')

    SEVERITY_MAP = {'high': 3, 'critical': 5}

    def create(self, validated_data):
        value = validated_data['value'].strip()
        entry_type = validated_data['type']
        severity_str = validated_data['severity']
        reason = validated_data.get('reason', '')

        # Derive link and domain from the value based on type
        if entry_type == 'domain':
            link = f'https://{value}'
            domain = value
            threat_type = 'blocked_domain'
        elif entry_type == 'url':
            link = value if value.startswith('http') else f'https://{value}'
            # Extract domain from URL
            from urllib.parse import urlparse
            parsed = urlparse(link)
            domain = parsed.netloc or value
            threat_type = 'blocked_url'
        else:  # ip
            link = value
            domain = value
            threat_type = 'blocked_ip'

        return Blacklist.objects.create(
            link=link,
            domain=domain,
            threat_type=threat_type,
            severity=self.SEVERITY_MAP.get(severity_str, 3),
            description=reason,
            source='admin',
        )


class BlacklistReadSerializer(serializers.ModelSerializer):
    """Read serializer that maps model fields to frontend-expected field names."""

    class Meta:
        model = Blacklist
        fields = [
            'id', 'link', 'domain', 'threat_type', 'threat_category',
            'severity', 'description', 'source', 'is_active', 'added_at', 'expires_at'
        ]


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'email', 'name', 'scanned_links', 'detected_threats',
            'accuracy_rate', 'is_active', 'is_staff', 'created_at', 'last_login'
        ]


class ScanCacheSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanCache
        fields = ['id', 'url', 'url_hash', 'scan_level', 'result', 'threat_level', 'risk_score', 'scanned_at', 'expires_at']


class ReportSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True, default='مستخدم غير معروف')
    scan_url = serializers.CharField(source='link', read_only=True)
    comment = serializers.CharField(source='description', read_only=True)

    class Meta:
        model = Report
        fields = [
            'id', 'link', 'category', 'status', 'severity',
            'reporter_name', 'is_anonymous', 'comment',
            'user_email', 'scan_url', 'created_at', 'tracking_number'
        ]
