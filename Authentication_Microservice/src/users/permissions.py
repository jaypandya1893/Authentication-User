from rest_framework import permissions

class CustomPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        if view.action == "create":
            return True
        elif request.user and request.user.is_authenticated:
            return True
        return False

    def has_object_permission(self, request, view, obj):
        if request.user.is_authenticated:
            if request.user.is_superuser or request.user.is_staff:
                return True
            if view.action in ["create", "retrieve"] and request.user.is_active:
                return True
        return False