import django
from django.contrib.auth import authenticate as dj_authenticate, get_user_model

from rest_framework import serializers


class Serializer(serializers.Serializer):
    @property
    def object(self):
        return self.validated_data


class PasswordField(serializers.CharField):

    def __init__(self, *args, **kwargs):
        if 'style' not in kwargs:
            kwargs['style'] = {'input_type': 'password'}
        else:
            kwargs['style']['input_type'] = 'password'
        super(PasswordField, self).__init__(*args, **kwargs)


def get_username_field():
    try:
        username_field = get_user_model().USERNAME_FIELD
    except AttributeError:
        username_field = 'username'

    return username_field


def get_username(user):
    try:
        username = user.get_username()
    except AttributeError:
        username = user.username

    return username


def authenticate(request=None, **credentials):
    if django.version < (1, 11):
        return dj_authenticate(**credentials)
    else:
        return dj_authenticate(request=request, **credentials)
