from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

# Create your models here.
from django.db import models
from colorfield.fields import ColorField
from django.core.validators import RegexValidator
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin


class CustomUserManager(BaseUserManager):
    def _create_user(self, phone, password, **extra_fields):
        if not phone:
            raise ValueError('Telefon raqam kiritishingiz shart!')
        if not password:
            raise ValueError('Maxfiy kod kiriting:')
        user = self.model(
            phone=phone,
            password = password,
            **extra_fields
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, phone, password, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(phone, password, **extra_fields)

    def create_superuser(self, phone, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_superuser', True)
        return self._create_user(phone, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    car = 'car'
    bus = 'bus'
    CHOISE1 = [
        (car, car),
        (bus, bus),
    ]
    car = models.CharField(
        max_length=10,
        choices=CHOISE1,
        default='car',
        null=True,
        blank=True,
    )
    # color = ColorField(default='#FF0000', null = True, blank = True)
    username = models.CharField(max_length=200)
    phone_regex = RegexValidator(regex='d{0,9}', message="Telefon raqamini +9989XXXXXXXX kabi kiriting!")
    phone = models.CharField(validators=[phone_regex], max_length=9, unique=True)
    otp = models.CharField(max_length=9, blank=True, null=True)
    password = models.CharField(max_length=2000)
    lastname = models.CharField(max_length=200)
    is_driver = models.BooleanField(default=False)
    is_user = models.BooleanField(default=False)
    car_marka = models.CharField(max_length=200)
    car_number = models.CharField(max_length=200)
    pasport = models.FileField(upload_to='pasport/', null=True, blank=True)
    image = models.FileField(upload_to='images/', null=True, blank=True)
    is_staff = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.username

class PhoneOtp(models.Model):
    phone_regex=RegexValidator(regex='d{0,9}', message="Telefon raqamini +9989XXXXXXXX kabi kiriting!")
    phone=models.CharField(validators=[phone_regex],max_length=9,unique=True)
    def __str__(self):
        massage=str(self.phone)+"ga jo'natildi"+str(self.otp)
        return massage

class ValidatedOtp(models.Model):
    phone_regex = RegexValidator(regex='d{0,9}', message="Telefon raqamini +9989XXXXXXXX kabi kiriting!")
    phone = models.CharField(validators=[phone_regex],max_length=9,unique=True)
    otp = models.CharField(max_length=9, blank=True, null=True)
    count = models.IntegerField(default=0, help_text='Kodni kiritishlar soni:')
    validated = models.BooleanField(default=False, help_text="Shaxsiy kabinetingizni yaratishingiz mumkin!")

    def __str__(self):
        return str(self.phone)

class Verification(models.Model):
    STATUS = (
        ('send', 'send'),
        ('confirmed', 'confirmed'),
    )
    phone = models.CharField(max_length=9, unique=True)
    verify_code = models.SmallIntegerField()
    is_verified = models.BooleanField(default=False)
    step_reset = models.CharField(max_length=10, null=True, blank=True, choices=STATUS)
    step_change_phone = models.CharField(max_length=30, null=True, blank=True, choices=STATUS)

    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.phone} --- {self.verify_code}"

class Order(models.Model):
    pending = 'pending'
    closed = 'closed'
    failed = 'failed'
    CHOISE1 = [
        (pending ,pending),
        (closed , closed),
        (failed , failed),
    ]
    status = models.CharField(
        max_length=10,
        choices=CHOISE1,
        default='pending',
    )
    gender = models.CharField(max_length=20, null=True, blank=True)
    driver = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='order')
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='buyurtmachi')
    from_to = models.CharField(max_length=200)
    to_to = models.CharField(max_length=200)
    time_to = models.TimeField()
    place = models.IntegerField()

    def __str__(self):
        return str(self.time_to)

class UserOrder(models.Model):
    men = 'men'
    women = 'women'
    CHOISE1 = [
        (men, 'men'),
        (women, 'women'),
    ]
    gender = models.CharField(
        max_length=10,
        choices=CHOISE1,
        default='men',
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='userorder')
    from_to =models.CharField(max_length=200)
    to_to = models.CharField(max_length=200)
    time_to = models.DateTimeField()
    place = models.IntegerField()
    oder_id = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='Userorder')

    def __str__(self):
        return self.user

