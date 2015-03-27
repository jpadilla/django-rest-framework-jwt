from django.db import models

# Django 1.8 includes UUIDField
if hasattr(models, 'UUIDField'):
    jti_field = models.UUIDField(editable=False, unique=True)
else:
    try:
        from uuidfield import UUIDField
        jti_field = UUIDField(auto=False, unique=True)
    except ImportError:
        jti_field = models.CharField(max_length=64,
                                     editable=False, unique=True)


class JWTBlackListToken(models.Model):
    jti = jti_field
    timestamp = models.DateTimeField(auto_now_add=True)
