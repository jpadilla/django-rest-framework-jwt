from django.contrib.auth import get_user_model

import rest_framework
from rest_framework import status
from rest_framework import serializers
from django.forms import widgets
from rest_framework.exceptions import APIException


class ValidationError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST

    def __init__(self, detail):
        self.detail = detail

    def __str__(self):
        return self.detail


if StrictVersion(rest_framework.VERSION) < StrictVersion('3.0.0'):
    class Serializer(serializers.Serializer):
        def is_valid(self, raise_exception=False):
            if self.errors and raise_exception:
                raise ValidationError(self.errors)

            return not self.errors


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
