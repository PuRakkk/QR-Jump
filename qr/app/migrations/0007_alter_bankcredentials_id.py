# Generated by Django 5.1.2 on 2025-02-25 08:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0006_alter_staticpayment_branch'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bankcredentials',
            name='id',
            field=models.BigAutoField(primary_key=True, serialize=False),
        ),
    ]
