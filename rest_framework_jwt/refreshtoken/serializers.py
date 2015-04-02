from .models import RefreshToken
from rest_framework import serializers


class RefreshTokenSerializer(serializers.ModelSerializer):
        """
        Serializer for refresh tokens (Not RefreshJWTToken)
        """

        class Meta:
            model = RefreshToken
            fields = ('key', 'user', 'created', 'app')
            read_only_fields = ('key', 'user', 'created')

        def validate(self, attrs):
            attrs['user'] = self.context['request'].user
            return attrs
