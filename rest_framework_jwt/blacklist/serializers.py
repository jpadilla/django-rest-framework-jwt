from rest_framework import serializers

from . import models


class JWTBlacklistTokenSerializer(serializers.ModelSerializer):
    jti = serializers.SerializerMethodField('get_jti_value')

    class Meta:
        model = models.JWTBlacklistToken

    def get_jti_value(self, obj):
        """Returns obj.jti manually due to py3 bug in django-uuidfield"""
        return obj.jti
