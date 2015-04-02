from calendar import timegm
from datetime import datetime

from rest_framework import mixins
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import status

from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.views import JSONWebTokenAPIView
from rest_framework_jwt.authentication import RefreshTokenAuthentication

from .permissions import IsOwnerOrAdmin
from .models import RefreshToken
from .serializers import RefreshTokenSerializer

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


class DelegateJSONWebToken(JSONWebTokenAPIView):
    """
    API View that checks the veracity of a refresh token, returning a JWT if it
    is valid.
    """
    authentication_classes = (RefreshTokenAuthentication, )

    def post(self, request):
        user = request.user
        payload = jwt_payload_handler(user)
        if api_settings.JWT_ALLOW_REFRESH:
            payload['orig_iat'] = timegm(datetime.utcnow().utctimetuple())
        return Response(
            {'token': jwt_encode_handler(payload)},
            status=status.HTTP_201_CREATED
        )


class RefreshTokenViewSet(mixins.RetrieveModelMixin,
                          mixins.CreateModelMixin,
                          mixins.DestroyModelMixin,
                          mixins.ListModelMixin,
                          viewsets.GenericViewSet):
    """
    API View that will Create/Delete/List `RefreshToken`.

    https://auth0.com/docs/refresh-token
    """
    permission_classes = (IsOwnerOrAdmin, )
    serializer_class = RefreshTokenSerializer
    queryset = RefreshToken.objects.all()
    lookup_field = 'key'

    def get_queryset(self):
        queryset = super(RefreshTokenViewSet, self).get_queryset()
        if self.request.user.is_superuser or self.request.user.is_staff:
            return queryset
        else:
            return queryset.filter(user=self.request.user)
