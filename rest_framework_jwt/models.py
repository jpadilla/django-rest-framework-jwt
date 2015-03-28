from django.db import models

from .compat import get_uuid_field

UUIDField = get_uuid_field()


class JWTBlackListToken(models.Model):
    jti = UUIDField()
    expires_at = models.DateTimeField()
    timestamp = models.DateTimeField(auto_now_add=True)
