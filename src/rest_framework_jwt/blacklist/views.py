from datetime import datetime

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from rest_framework_jwt.blacklist.models import BlacklistedToken

from ..authentication import JSONWebTokenAuthentication
from ..settings import api_settings
from ..utils import check_user, unix_epoch
from .serializers import BlacklistTokenSerializer


class BlacklistView(ModelViewSet):
    permission_classes = (IsAuthenticated, )
    authentication_classes = (JSONWebTokenAuthentication, )
    queryset = BlacklistedToken.objects.all().order_by('-blacklisted_at')
    serializer_class = BlacklistTokenSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.data.get('token')
        token_payload = JSONWebTokenAuthentication.jwt_decode_token(token)

        token_user = check_user(token_payload)

        if token_user.username != request.user.username:
            if not request.user.is_staff or token_user.is_superuser:
                return Response(status=status.HTTP_403_FORBIDDEN)

        iat = token_payload.get('iat', unix_epoch())
        expires_at_unix_time = iat + api_settings.JWT_EXPIRATION_DELTA.total_seconds()

        blacklisted_token, created = BlacklistedToken.objects.get_or_create(
            token=token,
            user=check_user(payload=token_payload),
            expires_at=datetime.utcfromtimestamp(expires_at_unix_time),
        )
        if created:
            blacklisted_token.blacklisted_by=request.user
            blacklisted_token.save()

        response = Response(
            JSONWebTokenAuthentication.jwt_create_response_payload(
                blacklisted_token.token, request.user, request
            )
        )
        return response
