from django.contrib import admin
from .models import CustomUser

# Register your models here.
class CustomuserAdmin(admin.ModelAdmin):
    list_display = ['email', 'first_name']
        


admin.site.register(CustomUser,CustomuserAdmin)


