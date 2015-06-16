import rest_framework
import rest_framework.exceptions
from distutils.version import StrictVersion


if StrictVersion(rest_framework.VERSION) < StrictVersion('3.0.0'):
    from rest_framework.serializers import Serializer
else:
    class Serializer(rest_framework.serializers.Serializer):
        @property
        def object(self):
            return self.validated_data

try:
    from rest_framework.serializers import CurrentUserDefault
except ImportError:
    # DRF 2.4
    class CurrentUserDefault(object):

        def __call__(self):
            pass
