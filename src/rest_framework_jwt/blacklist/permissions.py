
from rest_framework.permissions import BasePermission

from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.settings import api_settings


class IsAuthenticatedAndNotBlacklisted(BasePermission):
    message = 'You are not authenticated or have been blacklisted.'

    def has_permission(self, request, view):
        if request.user and not request.user.is_authenticated:
            return False

        if api_settings.JWT_AUTH_COOKIE:
            token = request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)
        else:
            token = request.auth.decode('utf-8')

        return not BlacklistedToken.objects.filter(token=token).exists()
