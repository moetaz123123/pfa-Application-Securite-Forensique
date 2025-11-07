from rest_framework import serializers
from .models import RemoteEvidence

class RemoteEvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = RemoteEvidence
        fields = ['user', 'remote_host', 'file', 'hash_value', 'collected_at']
