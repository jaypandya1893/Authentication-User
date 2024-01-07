from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

# Create your models here.

from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.db import models

class CustomUserManager(BaseUserManager):
    def create_user(self, phone_number, password=None, **extra_fields):
        if not phone_number:
            raise ValueError("The phone number field must be set")
        
        role = extra_fields.pop('role', UserModel.ADMIN)  
        
        user = self.model(phone_number=phone_number, role=role, **extra_fields)
        user.set_password(password)

        if role == UserModel.ADMIN:
            user.is_staff = True
            user.is_superuser = True
            user.is_active = True
        elif role == UserModel.MANAGER:
            user.is_staff = True
            user.is_active = True
        elif role == UserModel.EMPLOYEE:
            user.is_active = True

        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        return self.create_user(phone_number, password, **extra_fields)

class UserModel(AbstractUser):
    ADMIN = "admin"
    MANAGER = "manager"
    EMPLOYEE = "employee"

    USER_ROLE = (
        (ADMIN, "Admin"),
        (MANAGER, "Manager"),
        (EMPLOYEE, "Employee"),
    )
    role = models.CharField(_("Role"), choices=USER_ROLE, max_length=20, default=ADMIN)
    phone_number = models.CharField(_("Phone Number"), max_length=20, unique=True)
    email = models.EmailField(_("Email Address"), unique=True)
    otp = models.CharField(max_length=6, null=True, blank=True)
    
    USERNAME_FIELD = "phone_number"
    objects = CustomUserManager()

    def __str__(self):
        return self.first_name