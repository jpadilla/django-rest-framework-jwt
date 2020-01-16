from rest_framework.permissions import IsAdminUser


class IsSuperUser(IsAdminUser):
    """
    Permission check for superusers.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_superuser)
