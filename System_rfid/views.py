from django.shortcuts import render

# Create your views here.

from rest_framework import viewsets
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from .models import Role, Gates, Employees, Cards, Permissions, Access, Account, Employee_Roles
from .serializers import (
    RoleSerializer, GatesSerializer, EmployeesSerializer, CardsSerializer,
    PermissionsSerializer, AccessSerializer
)
from System_rfid.permissions import IsAdmin, IsManager, IsStaff, IsInter
import requests
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from rest_framework.decorators import api_view, permission_classes
from .forms import AccountCreationForm
from django.contrib.auth import authenticate, login
from django.contrib import messages
from datetime import datetime


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        # Wysyłanie danych logowania do endpointu JWT
        response = requests.post(
            'http://127.0.0.1:8000/token/',
            json={'username': username, 'password': password}
        )

        if response.status_code == 200:
            tokens = response.json()
            # Zapisanie tokenów w sesji
            request.session['access_token'] = tokens['access']
            request.session['refresh_token'] = tokens['refresh']

            # Logowanie użytkownika w Django
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('/')  # Przekierowanie po zalogowaniu
            else:
                return render(request, 'login.html', {'error': 'Invalid credentials'})

        else:
            # Błędne dane logowania
            return render(request, 'login.html', {'error': 'Invalid credentials'})

    return render(request, 'login.html')

@login_required
@permission_classes([IsAdmin])
def create_user(request):
    if request.method == 'POST':
        form = AccountCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('view_table', table_name='Accounts')
    else:
        form = AccountCreationForm()
    return render(request, 'create_user.html', {'form': form})

def validate_token(request):
    """
    Sprawdza obecność tokenu w sesji i obsługuje jego odświeżanie, jeśli wygaśnie.
    """
    access_token = request.session.get('access_token')
    if not access_token:
        return False

    # Testowanie ważności tokenu
    response = requests.get(
        'http://127.0.0.1:8000/some-endpoint/',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    if response.status_code == 401:  # Token wygasł
        refresh_token = request.session.get('refresh_token')
        if refresh_token:
            refresh_response = requests.post(
                'http://127.0.0.1:8000/token/refresh/',
                json={'refresh': refresh_token}
            )
            if refresh_response.status_code == 200:
                new_tokens = refresh_response.json()
                request.session['access_token'] = new_tokens['access']
                return True
        return False
    return True

@login_required
def home_view(request):
    """
    Dynamiczny widok główny, generujący dostępne tabele w zależności od roli użytkownika.
    Admin widzi wszystkie tabele, a Staff tylko dane powiązane z jego kontem.
    """

    if not validate_token(request):
        return redirect('login')

    # Lista dostępnych tabel
    tables = []
    user = request.user

    if user.role == 0:  # Admin
        tables = [
            {'name': 'Roles', 'url': 'view_table', 'params': {'table_name': 'Roles'}},
            {'name': 'Accounts', 'url': 'view_table', 'params': {'table_name': 'Accounts'}},
            {'name': 'Gates', 'url': 'view_table', 'params': {'table_name': 'Gates'}},
            {'name': 'Employees', 'url': 'view_table', 'params': {'table_name': 'Employees'}},
            {'name': 'Employees Roles', 'url': 'view_table', 'params': {'table_name': 'Employee Roles'}},
            {'name': 'Cards', 'url': 'view_table', 'params': {'table_name': 'Cards'}},
            {'name': 'Permissions', 'url': 'view_table', 'params': {'table_name': 'Permissions'}},
            {'name': 'Access', 'url': 'view_table', 'params': {'table_name': 'Access'}},
        ]
        return render(request, 'home_admin.html', {'tables': tables, 'user_role': request.user.get_role_display()})
    elif user.role == 1:  # Manager
        date_filter = request.GET.get('date')
        access_records = Access.objects.all().order_by('data')
        if date_filter:
            try:
                filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
                access_records = access_records.filter(data__date=filter_date)
            except ValueError:
                pass  # Ignoruj błędne daty

        # Widok ról, gdzie mają dostęp i kto ma te role
        roles = Role.objects.all()
        permissions = Permissions.objects.select_related('gate_id', 'role_id')
        role_filter = request.GET.get('role_id')
        if role_filter:
            permissions = permissions.filter(role_id=role_filter)

        # Widok konkretnego użytkownika (Manager wybiera użytkownika)
        user_filter = request.GET.get('user_id')
        user_access = Access.objects.none()
        user_roles = []
        user_permissions = []
        user_cards = []
        user_details = None

        if user_filter:
            try:
                specific_user = Employees.objects.get(id=user_filter)
                user_details = specific_user
                user_access = Access.objects.filter(employee_id=specific_user.id).order_by('data')
                user_roles = Employee_Roles.objects.filter(employee_id=specific_user.id)
                user_permissions = Permissions.objects.filter(role_id__in=[r.role_id.id for r in user_roles])
                user_cards = Cards.objects.filter(employee_id=specific_user.id)
            except Employees.DoesNotExist:
                pass  # Ignoruj błędne ID użytkownika

        return render(request, 'home_manager.html', {
            'access_records': access_records,
            'roles': roles,
            'permissions': permissions,
            'user_roles': user_roles,
            'user_permissions': user_permissions,
            'user_access': user_access,
            'user_cards': user_cards,
            'user_details': user_details,
            'date_filter': date_filter,
            'role_filter': role_filter,
            'user_filter': user_filter,
        })
        # Widok wszystkich access z filtrowaniem na dni(i sortowaniem po godzinie)
        # Widok ról gdzie maja dostep i kto ma je (filtrowanie przez konkretna role)
        # Widok konkretnego usera jego permissions,roles,access(sort by date),cards,dane

    else:  # Staff/Intership
        try:
            employee = Employees.objects.get(email=user.email)
            roles = Employee_Roles.objects.filter(employee_id=employee.id).select_related('role_id')
            role_names = [role.role_id.name for role in roles]
            permissions = Permissions.objects.filter(role_id__in=[role.role_id.id for role in roles])
        except Employees.DoesNotExist:
            employee = None
            roles = []
            role_names = []
            permissions = []

            # Pobieranie tabeli Access z filtrowaniem po dacie
        access_records = Access.objects.filter(employee_id=employee.id) if employee else Access.objects.none()

        # Obsługa filtrowania po dacie
        date_filter = request.GET.get('date')
        if date_filter:
            try:
                # Obsługa formatu YYYY-MM-DD
                filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
                access_records = access_records.filter(data__date=filter_date)
            except ValueError:
                pass  # Jeśli format jest nieprawidłowy, ignoruj filtrowanie

        return render(request, 'home_user.html', {
            'employee': employee,
            'roles': role_names,
            'permissions': permissions,
            'access_records': access_records,
            'date_filter': date_filter,
        })


@login_required
def view_table(request, table_name):
    """
    Dynamiczny widok przeglądania danych z dowolnej tabeli z obsługą usuwania rekordów.
    """
    if not validate_token(request):
        return redirect('login')

    models = {
        'Roles': Role,
        'Accounts': Account,
        'Gates': Gates,
        'Employees': Employees,
        'Employee Roles': Employee_Roles,
        'Cards': Cards,
        'Permissions': Permissions,
        'Access': Access,
    }

    model = models.get(table_name)
    if not model:
        return HttpResponseForbidden("Invalid table name.")

    user = request.user  # Aktualny użytkownik

    # Obsługa żądania POST do usunięcia rekordu
    if request.method == 'POST' and user.role == 0:  # Tylko Admin może usuwać
        delete_id = request.POST.get('delete_id')
        if delete_id:
            try:
                obj = model.objects.get(pk=delete_id)
                obj.delete()
                messages.success(request, f"Record with ID {delete_id} has been deleted.")
            except model.DoesNotExist:
                messages.error(request, "Record does not exist.")
            except Exception as e:
                messages.error(request, f"Error deleting record: {str(e)}")

    # Filtrowanie danych w zależności od roli użytkownika
    if user.role == 0:  # Admin - widzi wszystko
        data = model.objects.all()
    elif user.role == 2:  # Staff - widzi tylko dane powiązane z ich emailem
        if table_name == 'Employees':
            # Staff widzi tylko swój rekord w tabeli Employees
            data = model.objects.filter(email=user.email)
        elif table_name == 'Access':
            # Staff widzi tylko swoje dane w Access
            employee = Employees.objects.filter(email=user.email).first()
            if employee:
                data = model.objects.filter(employee_id=employee.id)
            else:
                data = model.objects.none()
        elif table_name == 'Cards':
            # Staff widzi tylko swoje karty
            employee = Employees.objects.filter(email=user.email).first()
            if employee:
                data = model.objects.filter(employee_id=employee.id)
            else:
                data = model.objects.none()
        elif table_name == 'Permissions':
            # Staff widzi tylko bramy, do których ma dostęp, na podstawie roli
            employee = Employees.objects.filter(email=user.email).first()
            if employee:
                role = Employee_Roles.objects.filter(employee_id=employee.id).values_list('role_id', flat=True).first()
                if role:
                    data = model.objects.filter(role_id=role)
                else:
                    data = model.objects.none()
            else:
                data = model.objects.none()
        else:
            # Staff nie ma dostępu do innych tabel
            return HttpResponseForbidden("You do not have permission to view this table.")
    else:
        # Inne role nie mają dostępu do tabel
        return HttpResponseForbidden("You do not have permission to view this table.")

    # Pobierz nazwy pól
    fields = [field.name for field in model._meta.fields]

    return render(request, 'view_table.html', {
        'data': data,
        'fields': fields,
        'table_name': table_name,
    })



from datetime import datetime

@login_required
def edit_table(request, table_name, object_id):
    """
    View for editing data in any table, including ForeignKey fields. Available only for Admins.
    """
    if not validate_token(request):
        return redirect('login')

    if request.user.role != 0:  # Only Admin
        return HttpResponseForbidden("You do not have permission to edit data.")

    # Map table names to models
    models = {
        'Roles': Role,
        'Accounts': Account,
        'Gates': Gates,
        'Employees': Employees,
        'Employee Roles': Employee_Roles,
        'Cards': Cards,
        'Permissions': Permissions,
        'Access': Access,
    }

    model = models.get(table_name)
    if not model:
        return HttpResponseForbidden("Invalid table name.")

    obj = get_object_or_404(model, pk=object_id)
    fields = []

    # Prepare fields and related objects for ForeignKey fields
    for field in model._meta.fields:
        if field.name != 'id':  # Skip the ID field
            field_data = {
                'name': field.name,
                'type': field.get_internal_type(),
                'choices': None  # Default: no choices
            }
            if field.related_model:  # If it's a ForeignKey, fetch related objects
                field_data['choices'] = list(field.related_model.objects.all())
            fields.append(field_data)

    if request.method == 'POST':
        for field in fields:
            field_name = field['name']
            value = request.POST.get(field_name)
            if value:
                # Handle DateTimeField
                if field['type'] == 'DateTimeField':
                    value = datetime.strptime(value, '%Y-%m-%dT%H:%M')
                # Handle DateField
                elif field['type'] == 'DateField':
                    value = datetime.strptime(value, '%Y-%m-%d').date()
                # Handle IntegerField
                elif field['type'] == 'IntegerField':
                    value = int(value)
                # Handle FloatField
                elif field['type'] == 'FloatField':
                    value = float(value)
                # Handle BooleanField
                elif field['type'] == 'BooleanField':
                    value = request.POST.get(field_name) == 'true'
                # Handle ForeignKey
                elif field['choices']:
                    value = field['choices'][0].__class__.objects.get(pk=value)
                setattr(obj, field_name, value)
        obj.save()
        return redirect('view_table', table_name=table_name)

    return render(request, 'edit_table.html', {
        'obj': obj,
        'fields': fields,
        'table_name': table_name,
    })

@login_required
def add_record(request, table_name):
    """
    View to add a new record to the table. Only Admins can access this.
    """
    if not validate_token(request):
        return redirect('login')

    if request.user.role != 0:  # Only Admin
        return HttpResponseForbidden("You do not have permission to add data.")

    models = {
        'Roles': Role,
        'Accounts': Account,
        'Gates': Gates,
        'Employees': Employees,
        'Employee Roles': Employee_Roles,
        'Cards': Cards,
        'Permissions': Permissions,
        'Access': Access,
    }

    model = models.get(table_name)
    if not model:
        return HttpResponseForbidden("Invalid table name.")

    fields = []

    # Prepare fields and dropdown options for ForeignKey fields
    for field in model._meta.fields:
        if field.name != 'id':  # Skip the ID field
            field_data = {
                'name': field.name,
                'type': field.get_internal_type(),
                'verbose_name': field.verbose_name,
                'choices': None
            }
            if field.related_model:  # If it's a ForeignKey, prepare options
                field_data['choices'] = list(field.related_model.objects.all())
            fields.append(field_data)

    if request.method == 'POST':
        record_data = {}
        for field in fields:
            field_name = field['name']
            value = request.POST.get(field_name)
            if value:
                if field['type'] == 'DateTimeField':
                    value = datetime.strptime(value, '%Y-%m-%dT%H:%M')
                elif field['type'] == 'DateField':
                    value = datetime.strptime(value, '%Y-%m-%d').date()
                elif field['type'] == 'IntegerField':
                    value = int(value)
                elif field['type'] == 'FloatField':
                    value = float(value)
                elif field['type'] == 'BooleanField':
                    value = request.POST.get(field_name) == 'true'
                elif field['choices']:  # Handle ForeignKey
                    value = field['choices'][0].__class__.objects.get(pk=value)
                record_data[field['name']] = value
        model.objects.create(**record_data)
        return redirect('view_table', table_name=table_name)

    return render(request, 'add_record.html', {
        'fields': fields,
        'table_name': table_name,
    })

@login_required
def view_accesses(request):
    """
    Widok wszystkich Access z filtrowaniem po dacie i sortowaniem od najnowszych.
    """
    if request.user.role != 1:  # Dostęp tylko dla Managera
        return HttpResponseForbidden("You do not have permission to view this page.")

    date_filter = request.GET.get('date')
    access_records = Access.objects.all().order_by('-data')  # Sortowanie od najnowszych

    if date_filter:
        try:
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            access_records = access_records.filter(data__date=filter_date)
        except ValueError:
            pass  # Ignoruj błędne daty

    return render(request, 'view_accesses.html', {
        'access_records': access_records,
        'date_filter': date_filter,
    })

from django.shortcuts import render
from django.http import HttpResponseForbidden
from datetime import datetime

@login_required
def view_specific_user(request):
    """
    Widok szczegółowy dla konkretnego użytkownika z filtrowaniem po dacie.
    """
    if request.user.role != 1:  # Dostęp tylko dla Managera
        return HttpResponseForbidden("You do not have permission to view this page.")

    user_filter = request.GET.get('user_id')  # ID użytkownika do filtrowania
    date_filter = request.GET.get('date')  # Filtr po dacie
    users = Employees.objects.all()  # Pobierz wszystkich pracowników
    user_details = None
    user_access = Access.objects.none()
    user_roles = []
    user_permissions = []
    user_cards = []

    if user_filter:
        try:
            specific_user = Employees.objects.get(id=user_filter)
            user_details = specific_user
            user_access = Access.objects.filter(employee_id=specific_user.id).order_by('-data')
            user_roles = Employee_Roles.objects.filter(employee_id=specific_user.id)
            user_permissions = Permissions.objects.filter(role_id__in=[r.role_id.id for r in user_roles])
            user_cards = Cards.objects.filter(employee_id=specific_user.id)

            if date_filter:
                try:
                    filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
                    user_access = user_access.filter(data__date=filter_date)
                except ValueError:
                    pass  # Ignoruj błędne daty

        except Employees.DoesNotExist:
            pass  # Ignoruj błędne ID użytkownika

    return render(request, 'view_specific_user.html', {
        'users': users,  # Dodaj listę użytkowników do template
        'user_details': user_details,
        'user_access': user_access,
        'user_roles': user_roles,
        'user_permissions': user_permissions,
        'user_cards': user_cards,
        'date_filter': date_filter,
    })


@login_required
def view_roles(request):
    """
    Widok ról, użytkowników przypisanych do ról oraz dostępnych bramek.
    """
    if request.user.role != 1:  # Dostęp tylko dla Managera
        return HttpResponseForbidden("You do not have permission to view this page.")

    role_filter = request.GET.get('role_id')
    roles = Role.objects.all()
    users_in_role = Employee_Roles.objects.none()
    permissions = Permissions.objects.none()
    role_name = None

    if role_filter:
        try:
            role = Role.objects.get(id=role_filter)
            role_name = role.name
            users_in_role = Employee_Roles.objects.filter(role_id=role.id).select_related('employee_id')
            permissions = Permissions.objects.filter(role_id=role.id)
        except Role.DoesNotExist:
            role_name = "Unknown Role"

    return render(request, 'view_roles.html', {
        'roles': roles,
        'users_in_role': users_in_role,
        'permissions': permissions,
        'role_filter': role_filter,
        'role_name': role_name,  # Nazwa roli
    })



def custom_404_view(request, exception):
    return redirect('/')