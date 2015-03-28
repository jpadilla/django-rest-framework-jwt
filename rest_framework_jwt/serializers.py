import jwt

from calendar import timegm
from datetime import datetime, timedelta

from django.contrib.auth import authenticate
from django.utils.translation import ugettext as _

from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_jwt import utils
from rest_framework_jwt.settings import api_settings

from .compat import Serializer

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_get_user_id_from_payload = api_settings.JWT_PAYLOAD_GET_USER_ID_HANDLER
jwt_blacklist_get_handler = api_settings.JWT_BLACKLIST_GET_HANDLER
jwt_blacklist_set_handler = api_settings.JWT_BLACKLIST_SET_HANDLER


class JSONWebTokenSerializer(Serializer):
    """
    Serializer class used to validate a username and password.

    'username' is identified by the custom UserModel.USERNAME_FIELD.

    Returns a JSON Web Token that can be used to authenticate later calls.
    """

    password = serializers.CharField(write_only=True)

    def __init__(self, *args, **kwargs):
        """
        Dynamically add the USERNAME_FIELD to self.fields.
        """
        super(JSONWebTokenSerializer, self).__init__(*args, **kwargs)
        self.fields[self.username_field] = serializers.CharField()

    @property
    def username_field(self):
        User = utils.get_user_model()

        try:
            return User.USERNAME_FIELD
        except AttributeError:
            return 'username'

    def validate(self, attrs):
        credentials = {
            self.username_field: attrs.get(self.username_field),
            'password': attrs.get('password')
        }

        if all(credentials.values()):
            user = authenticate(**credentials)

            if user:
                if not user.is_active:
                    msg = _('User account is disabled.')
                    raise serializers.ValidationError(msg)

                payload = jwt_payload_handler(user)

                # Include original issued at time for a brand new token,
                # to allow token refresh
                if api_settings.JWT_ALLOW_REFRESH:
                    payload['orig_iat'] = timegm(
                        datetime.utcnow().utctimetuple()
                    )

                return {
                    'token': jwt_encode_handler(payload),
                    'user': user
                }
            else:
                msg = _('Unable to login with provided credentials.')
                raise serializers.ValidationError(msg)
        else:
            msg = _('Must include "{username_field}" and "password".')
            msg = msg.format(username_field=self.username_field)
            raise serializers.ValidationError(msg)


class VerificationBaseSerializer(Serializer):
    """
    Abstract serializer used for verifying and refreshing JWTs.
    """
    token = serializers.CharField()

    def validate(self, attrs):
        msg = 'Please define a validate method.'
        raise NotImplementedError(msg)

    def _check_payload(self, token):
        # Check payload valid (based off of JSONWebTokenAuthentication,
        # may want to refactor)
        try:
            payload = jwt_decode_handler(token)
        except jwt.ExpiredSignature:
            msg = _('Signature has expired.')
            raise serializers.ValidationError(msg)
        except jwt.DecodeError:
            msg = _('Error decoding signature.')
            raise serializers.ValidationError(msg)

        # Check if the token has been blacklisted.
        if api_settings.JWT_ENABLE_BLACKLIST:
            blacklisted = jwt_blacklist_get_handler(payload)

            if blacklisted:
                msg = _('Token is blacklisted.')
                raise exceptions.AuthenticationFailed(msg)

        return payload

    def _check_user(self, payload):
        User = utils.get_user_model()
        # Make sure user exists (may want to refactor this)
        try:
            user_id = jwt_get_user_id_from_payload(payload)

            if user_id is not None:
                user = User.objects.get(pk=user_id, is_active=True)
            else:
                msg = _('Invalid payload.')
                raise serializers.ValidationError(msg)
        except User.DoesNotExist:
            msg = _("User doesn't exist.")
            raise serializers.ValidationError(msg)

        return user


class VerifyJSONWebTokenSerializer(VerificationBaseSerializer):
    """
    Check the veracity of an access token.
    """

    def validate(self, attrs):
        token = attrs['token']

        payload = self._check_payload(token=token)
        user = self._check_user(payload=payload)

        new_payload = jwt_payload_handler(user)

        return {
            'token': jwt_encode_handler(new_payload),
            'user': user
        }


class RefreshJSONWebTokenSerializer(VerificationBaseSerializer):
    """
    Refresh an access token.
    """

    def validate(self, attrs):
        token = attrs['token']

        payload = self._check_payload(token=token)
        user = self._check_user(payload=payload)

        # Get and check 'orig_iat'
        orig_iat = payload.get('orig_iat')

        if orig_iat:
            # Verify expiration
            refresh_limit = api_settings.JWT_REFRESH_EXPIRATION_DELTA

            if isinstance(refresh_limit, timedelta):
                refresh_limit = (refresh_limit.days * 24 * 3600 +
                                 refresh_limit.seconds)

            expiration_timestamp = orig_iat + int(refresh_limit)
            now_timestamp = timegm(datetime.utcnow().utctimetuple())

            if now_timestamp > expiration_timestamp:
                msg = _('Refresh has expired.')
                raise serializers.ValidationError(msg)
        else:
            msg = _('orig_iat field is required.')
            raise serializers.ValidationError(msg)

        new_payload = jwt_payload_handler(user)
        new_payload['orig_iat'] = orig_iat

        return {
            'token': jwt_encode_handler(new_payload),
            'user': user
        }


class BlacklistJSONWebTokenSerializer(VerificationBaseSerializer):
    """
    Blacklist an access token.
    """

    def validate(self, attrs):

        token = attrs['token']

        if not api_settings.JWT_ENABLE_BLACKLIST:
            msg = _('JWT_ENABLE_BLACKLIST is set to False.')
            raise serializers.ValidationError(msg)

        payload = self._check_payload(token=token)

        # Handle blacklisting a token.
        jwt_blacklist_set_handler(payload)

        user = self._check_user(payload=payload)

        return {
            'token': None,
            'user': user
        }
