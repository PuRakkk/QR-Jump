# Generated by Django 5.1.2 on 2025-02-24 10:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0007_remove_botusersstorage_user_pin'),
    ]

    operations = [
        migrations.AddField(
            model_name='botusersstorage',
            name='message_id',
            field=models.CharField(default='messsage_id_123', max_length=20),
        ),
    ]
