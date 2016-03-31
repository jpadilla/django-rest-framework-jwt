from django.contrib.auth import get_user_model
from distutils.version import StrictVersion

import rest_framework
from rest_framework import serializers
from django.forms import widgets


DRF_VERSION_INFO = StrictVersion(rest_framework.VERSION).version
DRF2 = DRF_VERSION_INFO[0] == 2
DRF3 = DRF_VERSION_INFO[0] == 3


if DRF2:
    class Serializer(serializers.Serializer):
        pass

    class PasswordField(serializers.CharField):
        widget = widgets.PasswordInput
else:
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
    except:
        username_field = 'username'

    return username_field


def get_username(user):
    try:
        username = user.get_username()
    except AttributeError:
        username = user.username

    return username


def get_request_data(request):
    if DRF2:
        data = request.DATA
    else:
        data = request.data
    return data
