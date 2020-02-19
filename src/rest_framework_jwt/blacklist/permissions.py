from rest_framework.permissions import BasePermission

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.compat import gettext_lazy as _


class IsNotBlacklisted(BasePermission):
    message = _('You have been blacklisted.')

    def has_permission(self, request, view):
        return not BlacklistedToken.objects.filter(
            token=JSONWebTokenAuthentication.get_token_from_request(request)
        ).exists()
