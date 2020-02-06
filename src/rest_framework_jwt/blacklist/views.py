from django.db import IntegrityError

from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import ValidationError
from rest_framework.viewsets import ModelViewSet

from rest_framework_jwt.blacklist.models import BlacklistedToken

from ..settings import api_settings
from .permissions import IsAuthenticatedAndNotBlacklisted
from .serializers import BlacklistTokenSerializer


class BlacklistView(ModelViewSet):
    queryset = BlacklistedToken.objects.all()
    serializer_class = BlacklistTokenSerializer
    permission_classes = (IsAuthenticatedAndNotBlacklisted, )

    def get_jwt_value(self, request):
        """
        Extract JWT token from request Authorization header.

        Splits Authorization header string into a list where first member
        represents authorization prefix and second member represents JWT token.

        If Authorization header was empty checks if JWT token should be
        retrieved from cookie.

        Returns JWT token.
        """

        auth = get_authorization_header(request).split()

        if not auth:
            if api_settings.JWT_IMPERSONATION_COOKIE:
                imp_user_token = request.COOKIES.get(api_settings.JWT_IMPERSONATION_COOKIE)
                if imp_user_token:
                    return imp_user_token

            if api_settings.JWT_AUTH_COOKIE:
                return request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)

        # Using decode because the token from the header is 'bytes' type and raises
        # error on serializer's `is_valid` method
        return auth[1].decode('utf-8')

    def create(self, request, *args, **kwargs):
        if 'token' not in request.data:
            request.data.update({'token': self.get_jwt_value(request)})

        return super(BlacklistView, self).create(request, *args, **kwargs)

    def perform_create(self, serializer):
        try:
            serializer.save()
        except IntegrityError:
            raise ValidationError('User\'s token has already been blacklisted.')
