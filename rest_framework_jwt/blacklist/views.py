from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.views import JSONWebTokenAPIView

from . import serializers

jwt_blacklist_response_handler = api_settings.JWT_BLACKLIST_RESPONSE_HANDLER


class BlacklistJSONWebToken(JSONWebTokenAPIView):
    """
    API View that blacklists a token
    """
    serializer_class = serializers.BlacklistJSONWebTokenSerializer
    response_payload_handler = staticmethod(
        jwt_blacklist_response_handler
    )


blacklist_jwt_token = BlacklistJSONWebToken.as_view()
