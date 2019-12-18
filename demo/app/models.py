# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


class UserWithProfile(AbstractUser):

    def save(self, *args, **kwargs):
        if not self.pk:
            self.profile = UserProfile(user=self)
        super(UserWithProfile, self).save(*args, **kwargs)


class UserProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name="profile",
        on_delete=models.CASCADE,
    )
