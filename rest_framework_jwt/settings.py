import datetime

from django.conf import settings
from rest_framework.settings import APISettings


USER_SETTINGS = getattr(settings, 'JWT_AUTH', None)

DEFAULTS = {
    'DEFAULT_JWT_ENCODE_HANDLER':
    'rest_framework_jwt.utils.jwt_encode_handler',

    'DEFAULT_JWT_DECODE_HANDLER':
    'rest_framework_jwt.utils.jwt_decode_handler',

    'DEFAULT_JWT_PAYLOAD_HANDLER':
    'rest_framework_jwt.utils.jwt_payload_handler',

    'JWT_SECRET_KEY': settings.SECRET_KEY,
    'JWT_ALGORITHM': 'HS256',
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_EXPIRATION_DELTA': datetime.timedelta(seconds=300)
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'DEFAULT_JWT_ENCODE_HANDLER',
    'DEFAULT_JWT_DECODE_HANDLER',
    'DEFAULT_JWT_PAYLOAD_HANDLER',
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
