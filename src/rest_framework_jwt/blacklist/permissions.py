from django.utils.encoding import force_str
from rest_framework.permissions import BasePermission

from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.settings import api_settings


class IsNotBlacklisted(BasePermission):
    message = 'You have been blacklisted.'

    def has_permission(self, request, view):
        if not request.auth:
            if api_settings.JWT_IMPERSONATION_COOKIE:
                imp_user_token = request.COOKIES.get(api_settings.JWT_IMPERSONATION_COOKIE)
                if imp_user_token:
                    token = imp_user_token

            if api_settings.JWT_AUTH_COOKIE:
                token = request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)

        else:
            token = force_str(request.auth)

        return not BlacklistedToken.objects.filter(token=token).exists()
