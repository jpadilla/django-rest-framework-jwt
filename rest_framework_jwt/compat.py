import rest_framework
import rest_framework.serializers
from django.forms import widgets
from distutils.version import StrictVersion


if StrictVersion(rest_framework.VERSION) < StrictVersion('3.0.0'):
    from rest_framework.serializers import Serializer, CharField

    class PasswordField(CharField):
        widget = widgets.PasswordInput
else:
    class Serializer(rest_framework.serializers.Serializer):
        @property
        def object(self):
            return self.validated_data

    class PasswordField(rest_framework.serializers.CharField):
        style = {
            'input_type': 'password'
        }


def get_user_model():
    try:
        from django.contrib.auth import get_user_model
    except ImportError:  # Django < 1.5
        from django.contrib.auth.models import User
    else:
        User = get_user_model()

    return User


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
    if hasattr(request, 'data'):
        data = request.data
    else:
        # DRF < 3.2
        data = request.DATA
    return data
