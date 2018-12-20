# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.contrib.auth.models import AbstractUser
from django.db import models


class UserWithProfile(AbstractUser):

    class Meta:
        app_label = 'tests'

    def save(self, *args, **kwargs):
        if not self.pk:
            self.profile = UserProfile(user=self)
        super(UserWithProfile, self).save(*args, **kwargs)


class UserProfile(models.Model):
    user = models.OneToOneField(UserWithProfile, related_name='profile')

    class Meta:
        app_label = 'tests'
