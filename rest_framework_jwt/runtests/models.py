from django.contrib.auth.models import User


class CustomUser(User):
    USERNAME_FIELD = 'email'
