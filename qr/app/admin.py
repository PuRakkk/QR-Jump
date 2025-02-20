from django.contrib import admin
from .models import SuperAdmin
from .models import Company, Branch, Staff, TransactionHistory, BankCredentials, StaticPayment
from django import forms

class BankCredentialsForm(forms.ModelForm):
    class Meta:
        model = BankCredentials
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['api_key'].widget = forms.TextInput(attrs={'placeholder': 'Enter API Key'})
        self.fields['public_key'].widget = forms.TextInput(attrs={'placeholder': 'Enter Public Key'})
        self.fields['merchant_id'].widget = forms.TextInput(attrs={'placeholder': 'Enter Merchant ID'})

@admin.register(BankCredentials)
class BankCredentialsAdmin(admin.ModelAdmin):
    form = BankCredentialsForm
    list_display = ('bank_name', 'is_active', 'truncated_api_key', 'truncated_public_key', 'truncated_merchant_id')
    filter_horizontal = ('branch',)

    def truncated_api_key(self, obj):
        return str(obj.api_key)[:20] + '...' if obj.api_key else ''
    truncated_api_key.short_description = 'API Key'

    def truncated_public_key(self, obj):
        return str(obj.public_key)[:20] + '...' if obj.public_key else ''
    truncated_public_key.short_description = 'Public Key'

    def truncated_merchant_id(self, obj):
        return str(obj.merchant_id)[:20] + '...' if obj.merchant_id else ''
    truncated_merchant_id.short_description = 'Merchant ID'

admin.site.register(Company)
admin.site.register(Branch)
admin.site.register(Staff)
admin.site.register(TransactionHistory)
admin.site.register(StaticPayment)

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