from rest_framework import serializers
from apps.scans.models import Scan, ScanSourceResult, WhitelistEntry, Blacklist, ScanCache
from apps.domains.models import Domain
from apps.accounts.models import User
from apps.reports.models import Report
from apps.feedback.models import AppRating
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError


class DashboardScanSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True, default='مستخدم غير معروف')

    class Meta:
        model = Scan
        fields = ['id', 'url', 'domain_name', 'final_verdict', 'safety_score', 'risk_score', 'safe', 'created_at', 'user_email', 'scan_level']


class ScanSourceResultSerializer(serializers.ModelSerializer):
    scan_url = serializers.CharField(source='scan.url', read_only=True)

    class Meta:
        model = ScanSourceResult
        fields = ['id', 'scan_url', 'source_type', 'verdict', 'risk_score', 'confidence', 'source_weight', 'latency_ms', 'checked_at']

class AppRatingSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.name', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = AppRating
        fields = ['id', 'rating', 'comment', 'created_at', 'user_name', 'user_email']


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
            'id', 'email', 'name', 'profile_image', 'scanned_links', 'detected_threats',
            'accuracy_rate', 'is_email_verified', 'is_active', 'is_staff', 'created_at', 'last_login'
        ]

class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    role = serializers.ChoiceField(choices=['admin', 'user'], write_only=True, default='user')

    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'role', 'profile_image']

    def validate_password(self, value):
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def create(self, validated_data):
        role = validated_data.pop('role', 'user')
        password = validated_data.pop('password')
        
        # Use create_user from manager to securely hash password
        user = User.objects.create_user(**validated_data, password=password)
        
        # Assign role
        if role == 'admin':
            user.is_staff = True
            user.save()
            
        return user

class UserUpdateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, allow_blank=True, style={'input_type': 'password'})
    role = serializers.ChoiceField(choices=['admin', 'user'], write_only=True, required=False)

    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'role', 'profile_image', 'is_active', 'is_email_verified']

    def validate_password(self, value):
        if not value:
            return value
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def update(self, instance, validated_data):
        role = validated_data.pop('role', None)
        password = validated_data.pop('password', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
            
        if password:
            instance.set_password(password)
            
        if role is not None:
            instance.is_staff = (role == 'admin')
            
        instance.save()
        return instance


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
            'user_email', 'scan_url', 'created_at', 'tracking_number',
            'investigation_notes', 'is_confirmed_threat', 'reviewed_at', 'resolved_at'
        ]

class ReportUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ['status', 'severity', 'category', 'investigation_notes', 'is_confirmed_threat']

    def update(self, instance, validated_data):
        status = validated_data.get('status', instance.status)
        notes = validated_data.get('investigation_notes', instance.investigation_notes)
        request = self.context.get('request')
        user = request.user if request else None

        if status == 'confirmed' and instance.status != 'confirmed':
            instance.confirm_threat(notes=notes, changed_by=user)
        elif status == 'resolved' and instance.status != 'resolved':
            instance.resolve_report(notes=notes, changed_by=user)
        elif status == 'rejected' and instance.status != 'rejected':
            instance.reject_report(notes=notes, changed_by=user)
        else:
            for attr, value in validated_data.items():
                setattr(instance, attr, value)
            instance.save()
            
        return instance
