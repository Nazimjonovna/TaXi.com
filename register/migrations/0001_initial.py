# Generated by Django 4.1.6 on 2023-03-11 05:57

import colorfield.fields
from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('car', models.CharField(blank=True, choices=[('car', 'car'), ('bus', 'bus')], default='car', max_length=10, null=True)),
                ('color', colorfield.fields.ColorField(blank=True, default='#FF0000', image_field=None, max_length=18, null=True, samples=None)),
                ('username', models.CharField(max_length=200)),
                ('phone', models.CharField(max_length=9, unique=True, validators=[django.core.validators.RegexValidator(message='Telefon raqamini +9989XXXXXXXX kabi kiriting!', regex='d{0,9}')])),
                ('otp', models.CharField(blank=True, max_length=9, null=True)),
                ('password', models.CharField(max_length=2000)),
                ('lastname', models.CharField(max_length=200)),
                ('is_driver', models.BooleanField(default=False)),
                ('is_user', models.BooleanField(default=False)),
                ('car_marka', models.CharField(max_length=200)),
                ('car_number', models.CharField(max_length=200)),
                ('pasport', models.FileField(blank=True, null=True, upload_to='pasport/')),
                ('image', models.FileField(blank=True, null=True, upload_to='images/')),
                ('is_staff', models.BooleanField(default=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_superuser', models.BooleanField(default=False)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Order',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('pending', 'pending'), ('closed', 'closed'), ('failed', 'failed')], default='pending', max_length=10)),
                ('gender', models.CharField(blank=True, max_length=20, null=True)),
                ('from_to', models.CharField(max_length=200)),
                ('to_to', models.CharField(max_length=200)),
                ('time_to', models.TimeField()),
                ('place', models.IntegerField()),
                ('driver', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='order', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='buyurtmachi', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='PhoneOtp',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone', models.CharField(max_length=9, unique=True, validators=[django.core.validators.RegexValidator(message='Telefon raqamini +9989XXXXXXXX kabi kiriting!', regex='d{0,9}')])),
            ],
        ),
        migrations.CreateModel(
            name='ValidatedOtp',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone', models.CharField(max_length=9, unique=True, validators=[django.core.validators.RegexValidator(message='Telefon raqamini +9989XXXXXXXX kabi kiriting!', regex='d{0,9}')])),
                ('otp', models.CharField(blank=True, max_length=9, null=True)),
                ('count', models.IntegerField(default=0, help_text='Kodni kiritishlar soni:')),
                ('validated', models.BooleanField(default=False, help_text='Shaxsiy kabinetingizni yaratishingiz mumkin!')),
            ],
        ),
        migrations.CreateModel(
            name='Verification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone', models.CharField(max_length=9, unique=True)),
                ('verify_code', models.SmallIntegerField()),
                ('is_verified', models.BooleanField(default=False)),
                ('step_reset', models.CharField(blank=True, choices=[('send', 'send'), ('confirmed', 'confirmed')], max_length=10, null=True)),
                ('step_change_phone', models.CharField(blank=True, choices=[('send', 'send'), ('confirmed', 'confirmed')], max_length=30, null=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='UserOrder',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('gender', models.CharField(choices=[('men', 'men'), ('women', 'women')], default='men', max_length=10)),
                ('from_to', models.CharField(max_length=200)),
                ('to_to', models.CharField(max_length=200)),
                ('time_to', models.DateTimeField()),
                ('place', models.IntegerField()),
                ('oder_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='Userorder', to='register.order')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='userorder', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
