from django.contrib.auth import get_user_model

from rest_framework.permissions import IsAuthenticated

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.utils import check_user


class CanBlacklist(IsAuthenticated):
    message = 'You are not allowed to blacklist this user\'s token.'

    def has_permission(self, request, view):
        user_id = request.data.get('user')

        user = get_user_model().objects.get(id=user_id)
        payload = JSONWebTokenAuthentication.jwt_create_payload(user)
        user = check_user(payload)

        if user.username != request.user.username:
            if not request.user.is_staff or user.is_superuser:
                return False

        return True
