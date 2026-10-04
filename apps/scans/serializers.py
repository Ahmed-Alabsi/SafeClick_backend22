# apps/scans/serializers.py
from rest_framework import serializers
from .models import Scan

class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = [
            'id', 'url', 'url_hash', 'domain', 'ip_address',
            'safe', 'score', 'risk_score', 'safety_score', 'result', 'details', 'threats_found',
            'threats_count', 'response_time', 'server_info', 'created_at', 'timestamp',
            'scan_scenario', 'reason'
        ]
    
    def to_representation(self, instance):
        """تنسيق البيانات للعرض"""
        data = super().to_representation(instance)
        
        # Human readable status summary for Flutter
        data['status_summary'] = f"{instance.result} - {instance.reason}"
        
        # Flutter Model Alignment
        data['ipAddress'] = data.get('ip_address')
        data['responseTime'] = data.get('response_time')
        data['timestamp'] = data.get('created_at')
        
        # [CRITICAL FIX]: Ensure history API returns the safety score (100 - risk_score)
        # instead of the legacy database risk_score, preventing 100% -> 0% flip on refresh.
        data['score'] = instance.safety_score
        
        # Detailed report passed through details field
        data['detailed_report'] = instance.details
        
        # إضافة الحالة النصية
        if data['safe'] == True:
            data['status_text'] = 'آمن'
            data['status_icon'] = '✅'
        elif data['safe'] == False:
            data['status_text'] = 'خطير'
            data['status_icon'] = '🔴'
        else:
            data['status_text'] = 'مشبوه'
            data['status_icon'] = '⚠️'
        
        return data


class ScanLinkSerializer(serializers.Serializer):
    link = serializers.URLField(required=True)
    scan_level = serializers.ChoiceField(choices=['basic', 'standard', 'deep'], default='deep', required=False)
    def validate_link(self, value):
        from apps.common.url_validator import validate_safe_url
        return validate_safe_url(value)