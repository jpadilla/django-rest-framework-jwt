from django.db import models

# Django 1.8 includes UUIDField
if hasattr(models, 'UUIDField'):
    import uuid
    jti_field = models.UUIDField(editable=False, unique=True)
else:
    from uuidfield import UUIDField
    jti_field = UUIDField(auto=False, unique=True)


class JWTBlackListToken(models.Model):
    jti = jti_field
    timestamp = models.DateTimeField(auto_now_add=True)
