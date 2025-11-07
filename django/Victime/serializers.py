from rest_framework import serializers
from .models import RemoteEvidence

class RemoteEvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = RemoteEvidence
        fields = ['user', 'remote_host', 'file', 'hash_value', 'collected_at']


from rest_framework import serializers
from .models import TrafficAnalysis

class TrafficAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrafficAnalysis
        fields = '__all__'

# youssef
from rest_framework import serializers
from .models import RemoteEvidence

class RemoteEvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = RemoteEvidence
        fields = ['user', 'remote_host', 'file', 'hash_value', 'collected_at']
