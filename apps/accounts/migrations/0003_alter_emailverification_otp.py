# Generated for SafeClick security hardening: OTP hashing support
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_guestsession_alter_ipattempt_ip_address_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='emailverification',
            name='otp',
            field=models.CharField(max_length=128),
        ),
    ]
