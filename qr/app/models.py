from django.db import models
from django.utils.timezone import now
from django.utils.timezone import localtime
from encrypted_model_fields.fields import EncryptedTextField

class Company(models.Model):
    com_id = models.AutoField(primary_key=True)
    com_name = models.CharField(max_length=150)
    com_email = models.EmailField(unique=True, blank=True, null=True)
    com_contact = models.CharField(max_length=15, blank=True, null=True)
    com_status = models.BooleanField(default=True)  
    com_created_at = models.DateTimeField(auto_now_add=True)
    telegram_id = models.BigIntegerField(unique=True)
    telegram_username = models.CharField(max_length=150)
    com_password = models.CharField(max_length=150, null=False, default='defaultpassword123')

    class Meta:
        db_table = 'qrjump_companies_storage'

    def __str__(self):
        return f"{self.com_name} - {self.com_email} - {self.com_contact} - {self.com_status} - {self.com_created_at} - {self.telegram_id} - {self.telegram_username}"


class Branch(models.Model):
    com_id = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='branches', db_column='com_id')
    br_kh_name = models.CharField(max_length=150)
    br_en_name = models.CharField(max_length=150)
    br_email = models.EmailField(unique=True,blank=True, null=True)
    br_password = models.CharField(max_length=150, blank=True, null=True)
    br_contact = models.CharField(max_length=15, blank=True, null=True)
    br_status = models.BooleanField(default=True)
    br_created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'qrjump_branches_storage'
    def __str__(self):
        return f"{self.com_id} - {self.br_kh_name} - {self.br_en_name} - {self.br_email} - {self.br_contact} - {self.br_status} - {self.br_created_at}"
    
class Staff(models.Model):
    branches = models.ManyToManyField(Branch, related_name='staff', db_table='qrjump_staff_users_branches')
    com_id = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='staff', db_column='com_id',null=True, blank=True)
    staff_id = models.AutoField(primary_key=True)
    staff_name = models.CharField(max_length=150) 
    staff_email = models.EmailField(blank=True, null=True)
    staff_contact = models.CharField(max_length=15, blank=True, null=True)
    staff_position = models.CharField(max_length=100, blank=True, null=True)
    staff_status = models.BooleanField(default=True)
    staff_created_at = models.DateTimeField(auto_now_add=True)
    staff_telegram_id = models.BigIntegerField(blank=True, null=True, unique=True)
    staff_telegram_username = models.CharField(max_length=150,unique=True)
    staff_user_pin = models.CharField(max_length=8, blank=True, null=True)

    class Meta:
        db_table = 'qrjump_staff_users_storage'

    def __str__(self):
        return f"{self.com_id} - {self.staff_name} - {self.staff_email} - {self.staff_contact} - {self.staff_position} - {self.staff_status} - {localtime(self.staff_created_at).strftime('%Y-%m-%d %H:%M:%S')} - {self.staff_telegram_id} - {self.staff_telegram_username} - {self.staff_user_pin}"
    
    
class TransactionHistory(models.Model):
    th_id = models.CharField(max_length=50, primary_key=True)
    th_telegram_id = models.BigIntegerField()
    com_id = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='transactions', db_column='com_id')
    br_id = models.ForeignKey(Branch, on_delete=models.CASCADE, related_name='transactions', db_column='br_id')
    staff_id = models.ForeignKey(Staff, on_delete=models.SET_NULL, related_name='transactions', null=True, blank=True, db_column='staff_id')
    th_datetime = models.DateTimeField(auto_now_add=True)
    th_amount = models.DecimalField(max_digits=10, decimal_places=2)
    th_currency = models.CharField(max_length=10)
    th_payment_type = models.CharField(max_length=50)
    th_created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'qrjump_transactions_history_storage'

    def __str__(self):
        return f"{self.th_telegram_id} - {self.com_id} - {self.br_id} - {self.staff_id} - {localtime(self.th_datetime).strftime('%Y-%m-%d %H:%M:%S')} - {self.th_amount} - {self.th_payment_type} - {localtime(self.th_created_at).strftime('%Y-%m-%d %H:%M:%S')}"
    
class BankCredentials(models.Model):
    BANK_CHOICES = [
        ('aba', 'ABA Bank'),
        ('acleda', 'Acleda Bank'),
        ('wing', 'Wing Bank'),
        ('bakong', 'Bakong Bank'),
    ]

    branch = models.ManyToManyField(Branch, related_name='bank_credentials')
    bank_name = models.CharField(max_length=50, choices=BANK_CHOICES)
    api_key = EncryptedTextField(models.CharField(max_length=255))
    public_key = EncryptedTextField(models.CharField(max_length=255))
    merchant_id = EncryptedTextField(models.CharField(max_length=255))
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        
        db_table = 'qrjump_bank_credentials_storage'

    def __str__(self):
        branch_names = ", ".join([branch.br_en_name for branch in self.branch.all()])
        return f"{branch_names} - {self.get_bank_name_display()}"
    
class SuperAdmin(models.Model):
    superadmin_id = models.AutoField(primary_key=True)
    superadmin_name = models.CharField(max_length=100)
    superadmin_email = models.EmailField(unique=True)
    superadmin_contact = models.CharField(max_length=15, null=True, blank=True)
    superadmin_password = models.CharField(max_length=255)
    superadmin_status = models.BooleanField(default=True)
    superadmin_created_at = models.DateTimeField(auto_now_add=True)
    branches = models.ManyToManyField(Branch, related_name='superadmin_branches', blank=True)
    
    def __str__(self):
        return self.superadmin_name

class StaticPayment(models.Model):
    payment_type = models.CharField(max_length=150)
    branch = models.ManyToManyField(Branch, related_name='statispayment')
    sp_created_at = models.DateTimeField(auto_now_add=True) 
    class Meta:
        db_table = 'qrjump_static_payments_storage'
    def __str__(self):
        return f"{self.payment_type} - {self.branch} - {self.sp_created_at}"

class BotUsersStorage(models.Model):
    telegram_id = models.BigIntegerField(unique=True, null=False)
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    full_name = models.CharField(max_length=100, null=True, blank=True)
    username = models.CharField(unique=True, null=False, max_length=100)
    telegram_language = models.CharField(max_length=10, null=False)
    user_choose_language = models.CharField(max_length=20, null=True, blank=True)
    user_status = models.CharField(max_length=50, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    visiter = models.CharField(max_length=20, null=True)
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    message_id = models.CharField(max_length=20, null=False, default='messsage_id_123')

    class Meta:
        db_table = 'qrjump_users_storage'
    
    def __str__(self):
        return f"{self.telegram_id} - {self.first_name} - {self.last_name} - {self.full_name} - {self.username} - {self.telegram_language} - {self.user_choose_language} - {self.user_status} - {self.created_at} - {self.visiter} - {self.phone_number} - {self.user_pin} - {self.message_id}"