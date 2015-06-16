from rest_framework import permissions


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Only admins or owners can have permission
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated()

    def has_object_permission(self, request, view, obj):
        """
        If user is staff or superuser or 'owner' of object return True
        Else return false.
        """
        if not request.user.is_authenticated():
            return False
        elif request.user.is_staff or request.user.is_superuser:
            return True
        else:
            return request.user == obj.user
