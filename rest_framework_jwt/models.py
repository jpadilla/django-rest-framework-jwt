import datetime

from django.db import models

from .compat import get_uuid_field

UUIDField = get_uuid_field()


class JWTBlackListToken(models.Model):
    jti = UUIDField()
    expires_at = models.DateTimeField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        now = datetime.datetime.now()
        return expires_at < now
