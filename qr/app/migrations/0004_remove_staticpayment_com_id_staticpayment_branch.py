# Generated by Django 5.1.2 on 2025-02-18 07:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_alter_bankcredentials_unique_together_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='staticpayment',
            name='com_id',
        ),
        migrations.AddField(
            model_name='staticpayment',
            name='branch',
            field=models.ManyToManyField(related_name='statispayment', to='app.branch'),
        ),
    ]
