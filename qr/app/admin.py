from django.contrib import admin
from .models import SuperAdmin
from .models import Company, Branch, Staff, TransactionHistory

admin.site.register(Company)
admin.site.register(Branch)
admin.site.register(Staff)
admin.site.register(TransactionHistory)

class SuperAdminAdmin(admin.ModelAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal Info', {'fields': ('email', 'phone_number')}),
        ('Permissions', {'fields': ('groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
    )

    list_display = ('username', 'email', 'phone_number', 'is_staff', 'is_superuser')
    search_fields = ('username', 'email', 'phone_number')

    readonly_fields = ('date_joined', 'last_login')

    ordering = ('-date_joined',)

@admin.register(SuperAdmin)
class SuperAdminAdmin(admin.ModelAdmin):
    list_display = ['superadmin_id', 'superadmin_name', 'superadmin_email', 'superadmin_contact', 'superadmin_status', 'superadmin_created_at']
    list_filter = ['superadmin_status', 'superadmin_created_at']

    search_fields = ['superadmin_name', 'superadmin_email']