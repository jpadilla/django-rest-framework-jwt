from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from rest_framework_jwt.blacklist.models import BlacklistedToken
from .serializers import BlacklistTokenSerializer
from ..authentication import JSONWebTokenAuthentication


class BlacklistView(ModelViewSet):
    permission_classes = (IsAuthenticated, )
    authentication_classes = (JSONWebTokenAuthentication, )
    queryset = BlacklistedToken.objects.all().order_by('-blacklisted_at')
    serializer_class = BlacklistTokenSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        token = serializer.data.get('token')
        token_payload = JSONWebTokenAuthentication.jwt_decode_token(token)
        token_username = JSONWebTokenAuthentication.jwt_get_username_from_payload(token_payload)

        if token_username != request.user.username:
            return Response(status=status.HTTP_403_FORBIDDEN)

        blacklisted_token = BlacklistedToken.objects.get_or_create(token=token)[0]
        response = Response(
            JSONWebTokenAuthentication.jwt_create_response_payload(
                blacklisted_token.token, request.user, request
            )
        )
        return response
