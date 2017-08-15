import uuid

from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import BaseUserManager
from django.db import models


class CustomUser(AbstractBaseUser):
    email = models.EmailField(max_length=255, unique=True)
    jwt_secret = models.UUIDField(
        'Token secret',
        help_text='Changing this will log out user everywhere',
        default=uuid.uuid4)

    objects = BaseUserManager()

    USERNAME_FIELD = 'email'

    class Meta:
        app_label = 'tests'


class CustomUserWithoutEmail(AbstractBaseUser):
    username = models.CharField(max_length=255, unique=True)

    objects = BaseUserManager()

    USERNAME_FIELD = 'username'

    class Meta:
        app_label = 'tests'


class CustomUserUUID(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=255, unique=True)

    objects = BaseUserManager()

    USERNAME_FIELD = 'email'

    class Meta:
        app_label = 'tests'
