import binascii
import os
import uuid

from django.conf import settings
from django.db import models
from django.utils.translation import ugettext_lazy as _


class Device(models.Model):
    """
    Device model used for permanent token authentication
    """
    permanent_token = models.CharField(max_length=255, unique=True)
    jwt_secret = models.UUIDField(default=uuid.uuid4, editable=False)
    created = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(_('Device name'), max_length=255)
    details = models.CharField(_('Device details'), max_length=255, blank=True)
    last_request_datetime = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.permanent_token:
            self.permanent_token = self.generate_key()

        return super(Device, self).save(*args, **kwargs)

    def generate_key(self):
        return binascii.hexlify(os.urandom(20)).decode()
