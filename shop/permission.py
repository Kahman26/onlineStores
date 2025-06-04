from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsSellerAndOwnerOrReadOnly(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return obj.seller == request.user or request.user.is_staff
        return obj.seller == request.user or request.user.is_staff


class IsAdminOnly(BasePermission):
    """
    Только админам разрешено.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_staff


class IsSellerOrAdmin(BasePermission):
    """
    Разрешает доступ продавцам или админам.
    """
    def has_permission(self, request, view):
        return request.user and (request.user.is_staff or request.user.groups.filter(name='seller').exists())


class IsOwnerOrAdmin(BasePermission):
    def has_object_permission(self, request, view, obj):
        return request.user.is_staff or obj.user == request.user


class IsSellerOnly(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated and
            (request.user.role == 'seller' or
             request.user.is_staff or
             request.user.groups.filter(name='seller').exists())
        )


class ReadOnlyOrSellerPermission(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        return request.user.is_authenticated and (
            request.user.role == 'seller' or request.user.is_staff
        )
