import rest_framework

from django.db import models

from distutils.version import StrictVersion
from functools import partial

from rest_framework import serializers


if StrictVersion(rest_framework.VERSION) < StrictVersion('3.0.0'):
    from rest_framework.serializers import Serializer
else:
    class Serializer(serializers.Serializer):
        @property
        def object(self):
            return self.validated_data


def get_uuid_field():
    """
    Returns a partial object that when called instantiates a UUIDField
    either from Django 1.8's native implementation, from django-uuidfield,
    or as a CharField as the final fallback.
    """
    if hasattr(models, 'UUIDField'):
        return partial(models.UUIDField, editable=False, unique=True)
    else:
        try:
            from uuidfield import UUIDField
            return partial(UUIDField, editable=False,
                           auto=False, unique=True)
        except ImportError:
            return partial(models.CharField, max_length=64,
                           editable=False, unique=True)
