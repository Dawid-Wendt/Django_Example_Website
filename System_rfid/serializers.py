Bfrom rest_framework import serializers
from .models import Role, Gates, Employees, Cards, Permissions, Access

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'

class GatesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Gates
        fields = '__all__'

class EmployeesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employees
        fields = '__all__'

class CardsSerializer(serializers.ModelSerializer):
    employee_id = EmployeesSerializer()  # Możesz użyć ID zamiast pełnego obiektu, jeśli to za dużo danych.

    class Meta:
        model = Cards
        fields = '__all__'


class PermissionsSerializer(serializers.ModelSerializer):
    gate_id = GatesSerializer()
    role_id = RoleSerializer()

    class Meta:
        model = Permissions
        fields = '__all__'

class AccessSerializer(serializers.ModelSerializer):
    employee_id = EmployeesSerializer()
    gate_id = GatesSerializer()

    class Meta:
        model = Access
        fields = '__all__'