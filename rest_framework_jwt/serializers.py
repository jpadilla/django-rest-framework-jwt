from calendar import timegm
from datetime import datetime, timedelta
import jwt

from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers

from rest_framework_jwt.settings import api_settings


jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_get_user_id_from_payload = api_settings.JWT_PAYLOAD_GET_USER_ID_HANDLER


class JSONWebTokenSerializer(serializers.Serializer):
    """
    Serializer class used to validate a username and password.

    'username' is identified by the custom UserModel.USERNAME_FIELD.

    Returns a JSON Web Token that can be used to authenticate later calls.
    """

    password = serializers.CharField(write_only=True)

    def __init__(self, *args, **kwargs):
        """Dynamically add the USERNAME_FIELD to self.fields."""
        super(JSONWebTokenSerializer, self).__init__(*args, **kwargs)
        self.fields[self.username_field] = serializers.CharField()

    @property
    def username_field(self):
        return get_user_model().USERNAME_FIELD

    def validate(self, attrs):
        credentials = {self.username_field: attrs.get(self.username_field),
                       'password': attrs.get('password')}
        if all(credentials.values()):
            user = authenticate(**credentials)

            if user:
                if not user.is_active:
                    msg = 'User account is disabled.'
                    raise serializers.ValidationError(msg)

                payload = jwt_payload_handler(user)

                # Include original issued at time for a brand new token,
                # to allow token refresh
                if api_settings.JWT_ALLOW_TOKEN_REFRESH:
                    payload['orig_iat'] = timegm(
                        datetime.utcnow().utctimetuple()
                    )

                return {
                    'token': jwt_encode_handler(payload)
                }
            else:
                msg = 'Unable to login with provided credentials.'
                raise serializers.ValidationError(msg)
        else:
            msg = 'Must include "username" and "password"'
            raise serializers.ValidationError(msg)


class RefreshJSONWebTokenSerializer(serializers.Serializer):
    """
    Check an access token
    """
    token = serializers.CharField()

    def validate(self, attrs):
        token = attrs['token']

        # Check payload valid (based off of JSONWebTokenAuthentication,
        # may want to refactor)
        try:
            payload = jwt_decode_handler(token)
        except jwt.ExpiredSignature:
            msg = 'Signature has expired.'
            raise serializers.ValidationError(msg)
        except jwt.DecodeError:
            msg = 'Error decoding signature.'
            raise serializers.ValidationError(msg)

        # Make sure user exists (may want to refactor this)
        User = get_user_model()
        try:
            user_id = jwt_get_user_id_from_payload(payload)
            if user_id:
                user = User.objects.get(pk=user_id, is_active=True)
            else:
                msg = 'Invalid payload'
                raise serializers.ValidationError(msg)
        except User.DoesNotExist:
            raise serializers.ValidationError("User doesn't exist")

        # Get and check 'orig_iat'
        orig_iat = payload.get('orig_iat')
        if orig_iat:
            # Verify expiration
            refresh_limit = api_settings.JWT_REFRESH_EXPIRATION_DELTA
            if isinstance(refresh_limit, timedelta):
                refresh_limit = (refresh_limit.days * 24 * 3600 +
                                 refresh_limit.seconds)
            expiration_timestamp = (
                orig_iat +
                int(refresh_limit)
            )
            now_timestamp = timegm(datetime.utcnow().utctimetuple())
            if now_timestamp > expiration_timestamp:
                raise serializers.ValidationError("Refresh has expired")
        else:
            raise serializers.ValidationError("orig_iat field is required")

        new_payload = jwt_payload_handler(user)
        new_payload['orig_iat'] = orig_iat

        return {
            'token': jwt_encode_handler(new_payload)
        }
