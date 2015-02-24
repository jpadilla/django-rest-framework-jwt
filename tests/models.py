from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager


class CustomUser(AbstractBaseUser):
    email = models.EmailField(max_length=255, unique=True)

    objects = BaseUserManager()

    USERNAME_FIELD = 'email'

    class Meta:
        app_label = 'tests'


class CustomUserWithBackend(models.Model):
    username = models.CharField(max_length=128, unique=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []
    is_active = True

    def get_username(self):
        return getattr(self, self.USERNAME_FIELD)

    def __unicode__(self):
        return self.get_username()

    def natural_key(self):
        return (self.get_username(),)

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return True

    def get_short_name(self):
        return self.username

    def get_full_name(self):
        return self.username


class CustomAuthenticationBackend(object):
    def authenticate(self, username=None):
        if username is None:
            return None
        try:
            return CustomUserWithBackend.objects.get(username=username)
        except CustomUserWithBackend.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return CustomUserWithBackend.objects.get(pk=user_id)
        except CustomUserWithBackend.DoesNotExist:
            return None
