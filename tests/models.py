from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager


class CustomUser(AbstractBaseUser):
    email = models.EmailField(max_length=255, unique=True)

    objects = BaseUserManager()

    USERNAME_FIELD = 'email'

    class Meta:
        app_label = 'tests'
