# -*- coding: utf-8 -*-

from django.conf import settings
from django.db import models

from rest_framework_jwt.settings import api_settings


class BlacklistedTokenManager(models.Manager):
    def delete_stale_tokens(self):
        return self.filter(
            expires_at__lt=api_settings.JWT_STALE_BLACKLISTED_TOKEN_EXPIRATION_TIME
        ).delete()


class BlacklistedToken(models.Model):
    token = models.TextField(db_index=True, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    expires_at = models.DateTimeField(db_index=True)
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    objects = BlacklistedTokenManager()

    def __str__(self):
        return 'Blacklisted token - {} - {}'.format(self.user, self.token)
