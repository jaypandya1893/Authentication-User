from django.contrib import admin
from users.models import UserModel

# Register your models here.

@admin.register(UserModel)
class UserModelAdmin(admin.ModelAdmin):
    list_display = [
        "id",'first_name','last_name','email','phone_number','password'
    ]
