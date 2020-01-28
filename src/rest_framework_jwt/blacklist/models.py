from datetime import datetime

from django.conf import settings
from django.db import models


class BlacklistedTokenManager(models.Manager):
    def delete_stale_tokens(self):
        return self.filter(expires_at__lt=datetime.utcnow()).delete()


class BlacklistedToken(models.Model):
    token = models.TextField(db_index=True, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='owner')
    expires_at = models.DateTimeField(db_index=True)
    blacklisted_at = models.DateTimeField(auto_now_add=True)
    blacklisted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )

    objects = BlacklistedTokenManager()

    def __str__(self):
        return 'Blacklisted token - {} - {}'.format(self.user, self.token)
