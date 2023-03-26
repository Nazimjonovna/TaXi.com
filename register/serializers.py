from rest_framework import serializers
from .models import User, Order, UserOrder, ValidatedOtp, Verification

class PhoneSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('phone',)


class Otpser(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('otp', 'phone')

class Validateser(serializers.ModelSerializer):
    class Meta:
        model = ValidatedOtp
        fields = ('phone', 'otp')

class Userserializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id','username','otp', 'phone', 'password', 'lastname', "is_user", 'is_driver', 'car_marka','car_number',  'pasport', 'image')

class AccSerializers(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'phone', 'password', 'lastname', "is_user", 'is_driver', 'car_marka','car_number',  'pasport', 'image')

class UserOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserOrder
        fields = ['id', 'user', 'from_to', 'to_to', 'time_to', 'place', 'gender', 'oder_id']

class DriverOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['id', 'driver', 'from_to', 'to_to', 'time_to', 'place', 'gender', 'status', ]

class SendSmsSerializer(serializers.Serializer):
    phone = serializers.IntegerField()
    text = serializers.CharField(max_length=256)

class ChangePasswordSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    password2 = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = User
        fields = ['old_password', 'new_password', 'password2']

    def validate(self, attrs):
        if attrs['new_password'] != attrs['password2']:
            raise serializers.ValidationError({'passwords': "The two password fields didn't match."})
        return super().validate(attrs)

    def update(self, instance, validated_data):
        if not instance.check_password(validated_data['old_password']):
            raise serializers.ValidationError({'old_password': 'wrong password'})
        instance.password = validated_data.get('password', instance.password)

        instance.set_password(validated_data['new_password'])
        instance.save()
        return instance

class VerifyCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Verification
        fields = ('phone', 'verify_code', 'step_change_phone')
        extra_kwargs = {
            'step_change_phone': {'read_only': True}
        }

    def update(self, instance, validated_data):
        verify_code = validated_data['verify_code']
        if instance.verify_code == verify_code:
            instance.is_verified = True
            if instance.step_reset == 'send':
                instance.step_reset = 'confirmed'
            if instance.step_change_phone:
                if instance.step_change_phone == 'send':
                    instance.step_change_phone = 'confirmed'
            instance.save()
            return instance
        else:
            raise serializers.ValidationError({'error': 'Phone number or verify code incorrect'})

class ResetPasswordSerializer(serializers.ModelSerializer):
    phone = serializers.CharField()
    new_password = serializers.CharField()
    re_new_password = serializers.CharField()

    class Meta:
        model = User
        fields = ('phone', 'new_password', 're_new_password')

    def validate(self, attrs):
        if not attrs['new_password']:
            raise serializers.ValidationError({'new_password': 'This field is required.'})

        if not attrs['re_new_password']:
            raise serializers.ValidationError({'re_new_password': 'This field is required.'})

        if attrs['new_password'] != attrs['re_new_password']:
            raise serializers.ValidationError({'passwords': "The two password fields didn't match."})

        return attrs