from django.urls import path
from .views import login_view, home_view, create_user,view_table, edit_table,add_record,view_accesses,view_specific_user,view_roles
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('login/', login_view, name='login'),
    path('', home_view, name='home'),
    path('create_user', create_user, name='create_user'),
    path('table/<str:table_name>/', view_table, name='view_table'),
    path('table/<str:table_name>/edit/<int:object_id>/', edit_table, name='edit_table'),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    path('table/<str:table_name>/add/', add_record, name='add_record'),
path('manager/accesses/', view_accesses, name='view_accesses'),
    path('manager/user/', view_specific_user, name='view_specific_user'),
    path('manager/roles/', view_roles, name='view_roles'),
]
