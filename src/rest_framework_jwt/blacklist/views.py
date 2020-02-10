from django.utils.encoding import force_str
from rest_framework.authentication import get_authorization_header
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet

from rest_framework_jwt.blacklist.models import BlacklistedToken

from ..settings import api_settings
from .serializers import BlacklistTokenSerializer


class BlacklistView(ModelViewSet):
    queryset = BlacklistedToken.objects.all()
    serializer_class = BlacklistTokenSerializer
    permission_classes = (IsAuthenticated, )

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

        # Using `force_str()` because the token from the header is 'bytes' type and raises
        # error on serializer's `is_valid()` method
        return force_str(auth[1])

    def create(self, request, *args, **kwargs):
        if 'token' not in request.data:
            request.data.update({'token': self.get_jwt_value(request)})

        return super(BlacklistView, self).create(request, *args, **kwargs)
