from django.contrib.auth.models import User, AbstractUser
from django.db import models

class Role(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Gates(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255,unique=True)
    state = models.BooleanField()

    def __str__(self):
        return f"{self.name}"

class Employees(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    surname = models.CharField(max_length=255)
    birth_date = models.DateField()
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)
    pesel = models.CharField(max_length=11,unique=True)

    def __str__(self):
        return f"{self.name} {self.surname}"

class Employee_Roles(models.Model):
    id = models.AutoField(primary_key=True)
    employee_id = models.ForeignKey(Employees, on_delete=models.CASCADE)
    role_id = models.ForeignKey(Role, on_delete=models.CASCADE)
    def __str__(self):
        return f"{self.employee_id.name} {self.employee_id.surname} {self.role_id.name}"

class Cards(models.Model):
    id = models.AutoField(primary_key=True)
    rfid_id = models.CharField(max_length=128)
    employee_id = models.ForeignKey(Employees, on_delete=models.CASCADE)
    
    def __str__(self):
        return f"{self.rfid_id} {self.employee_id.name} {self.employee_id.surname}"

class Permissions(models.Model):
    id = models.AutoField(primary_key=True)
    gate_id = models.ForeignKey(Gates,on_delete=models.CASCADE)
    role_id = models.ForeignKey(Role, on_delete=models.CASCADE)
    def __str__(self):
        return f"{self.gate_id.name} {self.role_id.name}"

class Access(models.Model):
    id = models.AutoField(primary_key=True)
    employee_id = models.ForeignKey(Employees, on_delete=models.CASCADE)
    gate_id = models.ForeignKey(Gates,on_delete=models.CASCADE)
    data = models.DateTimeField()
    access = models.BooleanField()
    def __str__(self):
        return f"{self.gate_id.name} {self.employee_id.name} {self.employee_id.surname} {self.data} {self.access}"

class Account(AbstractUser):
    ROLE_CHOICES = (
        (0, 'Admin'),
        (1, 'Manager'),
        (2, 'Staff'),
        (3, 'Internship'),

    )
    role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, default=2)
    email = models.EmailField(unique=True)

    def get_role_display(self):
        return dict(self.ROLE_CHOICES).get(self.role, 'Unknown')





