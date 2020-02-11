from django.utils.encoding import force_str
from rest_framework.permissions import BasePermission

from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.settings import api_settings


class IsNotBlacklisted(BasePermission):
    message = 'You have been blacklisted.'

    def has_permission(self, request, view):
        if api_settings.JWT_AUTH_COOKIE:
            token = request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)
        else:
            token = force_str(request.auth)

        return not BlacklistedToken.objects.filter(token=token).exists()
