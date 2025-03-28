# Generated by Django 5.1.4 on 2025-01-09 10:35

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('System_rfid', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='employees',
            name='role',
        ),
        migrations.CreateModel(
            name='Employee_Roles',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('employee_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='System_rfid.employees')),
                ('role_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='System_rfid.role')),
            ],
        ),
    ]
