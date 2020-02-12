from rest_framework.permissions import BasePermission

from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.utils import get_jwt_value


class IsNotBlacklisted(BasePermission):
    message = 'You have been blacklisted.'

    def has_permission(self, request, view):
        return not BlacklistedToken.objects.filter(
            token=get_jwt_value(request)
        ).exists()
