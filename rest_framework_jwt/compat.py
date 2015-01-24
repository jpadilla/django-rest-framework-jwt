import rest_framework
from distutils.version import StrictVersion


if StrictVersion(rest_framework.VERSION) < StrictVersion('3.0.0'):
    from rest_framework.serializers import Serializer
else:
    class Serializer(rest_framework.serializers.Serializer):
        @property
        def object(self):
            return self.validated_data
