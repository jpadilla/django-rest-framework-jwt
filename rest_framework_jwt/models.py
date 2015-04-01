from django.db import models
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _

from .compat import get_uuid_field

UUIDField = get_uuid_field()


class JWTBlacklistToken(models.Model):
    jti = UUIDField()
    expires = models.DateTimeField()
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('JWT Blacklist Token')
        verbose_name_plural = _('JWT Blacklist Tokens')

    def is_active(self):
        return self.expires > now()
