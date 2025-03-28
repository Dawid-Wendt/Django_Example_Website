from rest_framework import permissions

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 0 and request.user.is_authenticated

class IsManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 1 and request.user.is_authenticated

class IsStaff(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 2 and request.user.is_authenticated

class IsInter(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 3 and request.user.is_authenticated