from distutils.version import StrictVersion
from django.db.models import get_model
from django.forms import widgets
from django.utils.translation import ugettext as _
from rest_framework import serializers
import rest_framework

from rest_framework_jwt.settings import api_settings


jwt_username_field = api_settings.JWT_USERNAME_FIELD
jwt_user_identifier_app = api_settings.JWT_USER_IDENTIFIER_APP
jwt_user_identifier_model = api_settings.JWT_USER_IDENTIFIER_MODEL
jwt_user_identifier_field = api_settings.JWT_USER_IDENTIFIER_FIELD


if StrictVersion(rest_framework.VERSION) < StrictVersion('3.0.0'):
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


def get_user_model():
    """ Return the model that should be used to get a user from the db. """
    try:
        from django.contrib.auth import get_user_model
    except ImportError:  # Django < 1.5
        from django.contrib.auth.models import User
    else:
        User = get_user_model()

    return User


def get_username_field():
    """ Return the field that should be used to authenticate a user against the db. """
    if jwt_username_field:
        return jwt_username_field

    try:
        username_field = get_user_model().USERNAME_FIELD
    except:
        username_field = 'username'

    return username_field


def get_user_identifier_field():
    """ Return the field that should be used to identify a user in a JWT. """
    if jwt_user_identifier_app and jwt_user_identifier_model and\
        jwt_user_identifier_field:
        return jwt_user_identifier_field

    try:
        user_identifier_field = get_user_model().USERNAME_FIELD
    except:
        user_identifier_field = 'username'

    return user_identifier_field


def get_user_from_payload(payload):
    """ Return instance of User from a payload. """
    # unfortunately need to import here to avoid circular import
    jwt_payload_get_user_identifier_handler =\
        api_settings.JWT_PAYLOAD_GET_USER_IDENTIFIER_HANDLER
    user_identifier = jwt_payload_get_user_identifier_handler(payload)

    if not user_identifier:
        msg = _('Invalid payload.')
        raise ValueError(msg)

    if jwt_user_identifier_app and jwt_user_identifier_model and\
        jwt_user_identifier_field:
        user_identifier_field = get_user_identifier_field()
        identifier_model_class = get_model(jwt_user_identifier_app,
            jwt_user_identifier_model)
        try:
            identifier_model = identifier_model_class.objects.get(
                **{user_identifier_field: user_identifier})
        except identifier_model.DoesNotExist:
            msg = _('Invalid payload.')
            raise ValueError(msg)
        user = identifier_model.user
        if not user:
            # in case of a nullable FK from the custom model to User
            msg = _('Invalid payload.')
            raise ValueError(msg)
    else:
        User = get_user_model()
        try:
            user = User.objects.get_by_natural_key(user_identifier)
        except User.DoesNotExist:
            msg = _('Invalid payload.')
            raise ValueError(msg)
    if not user.is_active:
        msg = _('User account is disabled.')
        raise ValueError(msg)
    return user


def get_user_identifier(user):
    """ Return the attribute that should be used to identify a user in a JWT. """
    custom_user_identifier = get_custom_user_identifier(user)
    if custom_user_identifier:
        return custom_user_identifier

    try:
        username = user.get_username()
    except AttributeError:
        username = user.username

    return username


def get_custom_user_identifier(user):
    """ Return the custom identifier for the user or None if not configured. """
    if jwt_user_identifier_app and jwt_user_identifier_model and\
        jwt_user_identifier_field:
        identifier_model_class = get_model(jwt_user_identifier_app,
            jwt_user_identifier_model)
        identifier_model = identifier_model_class.objects.get(user=user)
        return getattr(identifier_model, jwt_user_identifier_field)
    else:
        return None


def get_request_data(request):
    if getattr(request, 'data', None):
        data = request.data
    else:
        # DRF < 3.2
        data = request.DATA

    return data
