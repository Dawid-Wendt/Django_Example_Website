# Generated by Django 5.1.4 on 2025-01-14 07:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('System_rfid', '0002_remove_employees_role_employee_roles'),
    ]

    operations = [
        migrations.AlterField(
            model_name='access',
            name='data',
            field=models.DateTimeField(),
        ),
    ]
