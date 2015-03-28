import pytz
import datetime

from django.db import models
from django.utils.translation import ugettext_lazy as _

from .compat import get_uuid_field

UUIDField = get_uuid_field()


class JWTBlackListToken(models.Model):
    jti = UUIDField()
    expires = models.DateTimeField()
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('JWT Blacklist Token')
        verbose_name_plural = _('JWT Blacklist Tokens')

    def is_expired(self):
        now = datetime.datetime.now(pytz.utc)
        return self.expires < now
