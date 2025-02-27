from rest_framework import serializers
from .models import Company, Branch, Staff, TransactionHistory, BankCredentials, StaticPayment, BotUsersStorage


class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = '__all__'

class BankCredentialsSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankCredentials
        fields = ['bank_name', 'api_key', 'public_key', 'merchant_id', 'is_active', 'created_at', 'updated_at']
        extra_kwargs = {
            'api_key': {'allow_blank': False, 'required': True, 'allow_null': False},
        }

class StaticPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = StaticPayment
        fields = ['payment_type']

class BranchSerializer(serializers.ModelSerializer):
    bank_credentials = BankCredentialsSerializer(many=True, read_only=True)
    payment_types = serializers.SerializerMethodField()
    class Meta:
        model = Branch
        fields = [
            'id', 'com_id', 'br_kh_name', 'br_en_name', 'br_email', 
            'br_password', 'br_contact', 'br_status', 'br_created_at',
            'bank_credentials','payment_types'
        ]
    def get_payment_types(self, obj):
        return [static_payment.payment_type for static_payment in obj.statispayment.all()]

class StaffSerializer(serializers.ModelSerializer):
    branches = BranchSerializer(many=True, required=False)

    class Meta:
        model = Staff
        fields = '__all__'

    def update(self, instance, validated_data):
        branches_data = validated_data.pop('branches', []) 

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        if branches_data:
            instance.branches.clear() 
            branch_instances = Branch.objects.filter(id__in=[branch['id'] for branch in branches_data])
            instance.branches.add(*branch_instances) 
        
        instance.save()
        return instance


class TransactionHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = TransactionHistory
        fields = '__all__'


class BotUsersStorageSerializer(serializers.ModelSerializer):
    class Meta:
        model = BotUsersStorage
        fields = '__all__'