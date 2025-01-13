from rest_framework import serializers
from .models import Company, Branch, Staff, TransactionHistory


class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = '__all__'

class BranchSerializer(serializers.ModelSerializer):
    class Meta:
        model = Branch
        fields = '__all__'

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
