from django.shortcuts import render
import pytz
from django.conf import settings
import datetime as d
from django.utils.translation import gettext_lazy as _
from random import randint
from get_sms import Getsms
from rest_framework.views import APIView
from rest_framework import status,  generics, parsers
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from .models import User, Order, UserOrder, Verification, ValidatedOtp
from .serializers import (Userserializer, DriverAccSerializers, UserOrderSerializer,
                          DriverOrderSerializer , SendSmsSerializer, PhoneSerializer,
                          Otpser, ChangePasswordSerializer, VerifyCodeSerializer,
                          ResetPasswordSerializer,)

utc = pytz.timezone(settings.TIME_ZONE)
min = 1
def send_sms(phone, step_reset=None, change_phone=None):
    try:
        verify_code = randint(1111, 9999)
        try:
            obj = Verification.objects.get(phone=phone)
        except Verification.DoesNotExist:
            obj = Verification(phone=phone, verify_code=verify_code)
            obj.step_reset=step_reset
            obj.step_change_phone=change_phone
            obj.save()
            context = {'number': str(obj.phone), 'verify_code': obj.verify_code,
                       'lifetime': _(f"{min} minutes")}
            return context
        time_now = d.datetime.now(utc)
        diff = time_now - obj.created
        three_minute = d.timedelta(minutes=min)
        if diff <= three_minute:
            time_left = str(three_minute - diff)
            return {'message': _(f"Try again in {time_left[3:4]} minute {time_left[5:7]} seconds")}
        obj.delete()
        obj = Verification(phone=phone)
        obj.verify_code=verify_code
        obj.step_reset=step_reset
        obj.step_change_phone=change_phone
        obj.save()
        context = {'number': str(obj.phone), 'verify_code': obj.verify_code, 'lifetime': _(f"{min} minutes")}
        return context
    except Exception as e:
        print(f"\n[ERROR] error in send_sms <<<{e}>>>\n")

import requests

# requests.post("http://sms-service.m1.uz/send_sms/", {"number":998946382901, "text":"Hello"})


class SendSms(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = SendSmsSerializer

    def post(self, request):
        serializer = SendSmsSerializer(data=request.data)
        if serializer.is_valid():
            login = "HelpCode"
            password = "B180Ns49DnRbuPX9686R"
            nickname = "HelpCodeUz"

            message = Getsms(login=login, password=password, nickname=nickname)
            numbers = [serializer.data['phone']]

            results = message.send_message(numbers=numbers, text=serializer.data['text'])

            if 'error' in results:
                print(results)

            for result in results:
                print(result)
            return Response({"msg": f"Send SMS successfully to {serializer.data['phone']}"})
        else:
            return Response({"msg": serializer.errors})

# Create your views here.
class Register(APIView):
    permission_classes = [AllowAny, ]

    @swagger_auto_schema(request_body=Userserializer)
    def post(self, request, *args, **kwargs):
        password = request.data['password'][:]
        request.data['password'] = make_password(password)
        serializer = Userserializer(data=request.data)
        try:
            verify = ValidatedOtp.objects.filter(phone__iexact=request.data['phone'], validated=True)
            if verify.exists():
                if serializer.is_valid(raise_exception=True):
                    user_obj = User(phone=request.data['phone'])
                    user_obj.password = request.data['password']
                    user_obj.username=request.data['username']
                    # user_obj.otp = request.data['otp']
                    # user_obj.save()
                    serializer.save()

            access_token = AccessToken().for_user(user_obj)
            refresh_token = RefreshToken().for_user(user_obj)
            return Response({
                "access": str(access_token),
                "refresh": str(refresh_token),
                "user": serializer.data,
            })
        except Exception as e:
            return Response({"error": str(e)})

        # except:
        #     return Response({
        #         "status": False,
        #         "detail": "Siz bir martalik mahfiy kodni kiritmgansiz. Shuning uchun ro'yhatdan o'ta olmaysiz!"
        #     })


class PhoneView(APIView):
    queryset = User.objects.all()
    serializer_class = PhoneSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(request_body=PhoneSerializer, tags=['Register'])
    def post(self, request, *args, **kwargs):
        phone = request.data.get("phone")
        if phone.isdigit() and len(phone) > 8:
            user = User.objects.filter(phone__iexact=phone)
            if user.exists():
                return Response({
                    "status": False,
                    "detail": "Bu raqam avval registerdan otgan."
                })
            else:
                otp = send_sms(phone)
                if 'verify_code' in otp:
                    code = str(otp['verify_code'])
                    try:
                        validate = ValidatedOtp.objects.get(phone=phone)
                        if validate.validated:
                            validate.otp = code
                            validate.validated = False
                            validate.save()

                    except ValidatedOtp.DoesNotExist as e:
                        phon = ValidatedOtp.objects.filter(phone__iexact=phone)
                        if not phon.exists():
                            ValidatedOtp.objects.create(phone=phone, otp=code, validated=False)
                        else:
                            Response({"number": "mavjud"})

                return Response({
                    "status": True,
                    "detail": "SMS xabarnoma jo'natildi",
                    "code": otp  # <--vaqtinchalik qo'shildi
                })
        else:
            if len(phone) < 8:
                return Response({"detail": "Telefon raqamingizni kod bilan kiriting!"})
            else:
                return Response({
                    "status": False,
                    "detail": "Telefon raqamni kiriting ."
                })

    def send_otp(phone, otp):
        if phone:
            otp = randint(999, 9999)
            print(otp)
            return otp
        else:
            return False


class OtpView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(request_body=Otpser, tags=['Register'])
    def post(self, request):
        phone = request.data.get('phone', True)
        code_send = request.data.get('otp', True)
        if not phone and code_send:
            return Response({
                'status': False,
                'detail': 'Otpni va phone ni kiriting'
            })
        try:
            verify = ValidatedOtp.objects.get(phone=phone, validated=False)
            if verify.otp == code_send:
                verify.count += 1
                verify.validated = True
                verify.save()

                return Response({
                    'status': True,
                    'detail': "Otp to'g'ri"
                })
            else:
                return Response({
                    'status': False,
                    'error': "Otpni to'g'ri kiriting"})

        except ValidatedOtp.DoesNotExist as e:
            return Response({
                'error': "Otp aktiv emas yoki mavjud emas, boshqa otp oling"
            })

class ValidatedOtpView(APIView):
    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone', False)
        otp_sent = request.data.get('otp', False)

        if phone and otp_sent:
            old = ValidatedOtp.objects.filter(phone__iexact=phone)
            if old.exists():
                old = old.first()
                otp = old.otp
                if str(otp_sent) == str(otp):
                    old.validated = True
                    old.save()

class LogoutUserView(APIView):
    permission_classes = [AllowAny, ]

    def post(self, request):
        response=Response()
        response.delete_cookie(key='refreshToken')
        response.data={
            'massage':'success'
        }
        return response

class DriverAcc(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated, ]
    parser_classes = [parsers.MultiPartParser]
    queryset = User.objects.all()
    serializer_class = DriverAccSerializers

    @swagger_auto_schema(request_body=DriverAccSerializers)
    def patch(self, request, pk):
        user = User.objects.get(id=pk)
        print(user)
        if user.phone != request.data['phone']:
            user.phone = request.data.get('phone', user.email)
            us = User.objects.filter(phone=request.data['phone'])
            if not us.exists():
                user.save()
                access_token = AccessToken().for_user(user)
                refresh_token = RefreshToken().for_user(user)
                serializer = DriverAccSerializers(instance=user, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response({
                        "access_token": str(access_token),
                        "refresh_token": str(refresh_token),
                        "user": serializer.data,
                    })
                else:
                    return Response({'User not found'},
                                    serializer.errors)
            else:
                return Response({"Mavjud nomer"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            user.save()
            serializer = DriverAccSerializers(instance=user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "user": serializer.data,
                })
            else:
                return Response({'User not found'},
                                serializer.errors)

class ChangePasswordView(generics.UpdateAPIView):

    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer
    my_tags = ['Change-Password']

    @swagger_auto_schema(request_body=ChangePasswordSerializer)
    def put(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(instance=self.request.user, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'msg': "Password muvafaqiyatli o'zgartirildi"}, status=status.HTTP_200_OK)

class OrderView(APIView):
    permission_classes = [IsAuthenticated, ]
    serializer_class = DriverOrderSerializer

    # @swagger_auto_schema(request_body=DriverOrderSerializer)
    def get(self, request, pk):
        try:
            order = Order.objects.get(id=pk)
        except Order.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        if request.method == 'GET':
            serializer = DriverOrderSerializer(order)
            return Response(serializer.data)

    @swagger_auto_schema(request_body=DriverOrderSerializer)
    def post(self, request, *args, **kwargs):
        user = User.objects.get(id=request.data['driver'])
        if user.is_driver:
            serializer = DriverOrderSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            else:
                return Response(serializer.errors)

    def delete(self, request, pk):
        order = Order.objects.get(id=pk)

        if order:
            order.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(status=status.HTTP_400_BAD_REQUEST)

class UserOrderView(APIView):
    permission_classes = [IsAuthenticated, ]
    serializer_class = UserOrderSerializer

    @swagger_auto_schema(request_body=UserOrderSerializer)
    def post(self, request, *args, **kwargs):
        user = User.objects.get(id=request.data['user'])
        if user.is_user:
            serializer = UserOrderSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                order = Order.objects.get(id=request.data['oder_id'])
                qiymat = order.place - int(request.data['place'])
                if qiymat> 0:
                    serializer.validated_data['status']='pending'
                    serializer.save()
                    order.place = order.place - int(request.data['place'])
                    order.save()
                    return Response(
                        serializer.data,
                    )
                elif qiymat==0:
                    serializer.validated_data['status']='closed'
                    serializer.save()
                    order.place = order.place - int(request.data['place'])
                    order.save()
                    return Response(
                        serializer.data,
                    )
                elif qiymat<0:
                    serializer.save()
                    return Response({
                        "Message":'Uzr Bu Buyurtmada joy yetarli emas!'
                    })
                return Response(serializer.data)
            else:
                return Response(serializer.errors)

class VerifyCodeView(APIView):
    serializer_class = VerifyCodeSerializer
    permission_classes = [AllowAny]
    queryset = Verification.objects.all()

    @swagger_auto_schema(request_body=VerifyCodeSerializer, tags=['Password-Reset'])
    def put(self, request, *args, **kwargs):
        data = request.data
        try:
            obj = Verification.objects.get(phone=data['phone'])
            serializer = VerifyCodeSerializer(instance=obj, data=data)
            if serializer.is_valid():
                serializer.save()
                if serializer.data['step_change_phone'] == 'confirmed':
                    user = request.user
                    user.phone = data['phone']
                    user.save()
                    return Response({'message': 'Your phone number has been successfully changed!'},
                                status=status.HTTP_202_ACCEPTED)
                return Response({'message': 'This phone number has been successfully verified!'},
                                status=status.HTTP_202_ACCEPTED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Verification.DoesNotExist:
            return Response({'error': 'Phone number or verify code incorrect!'}, statusis_pupil=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PhoneSerializer
    my_tags = ['Password-Reset']

    @swagger_auto_schema(request_body=PhoneSerializer, tags=['Password-Reset'])
    def post(self, request):
        data = request.data
        if data.get('phone'):
            phone = data['phone']
            user = User.objects.filter(phone__iexact=phone)
            if user.exists():
                user = user.first()
                context = send_sms(phone)
                return Response(context, status=status.HTTP_208_ALREADY_REPORTED)
            return Response({'msg': _('User not found!')})
        return Response({'msg': _("Enter phone number")}, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordVerifyCode(VerifyCodeView):
    my_tags = ['Password-Reset']

class ResetPasswordConfirm(APIView):
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordSerializer

    @swagger_auto_schema(request_body=ResetPasswordSerializer, tags=['Password-Reset'])
    def put(self, request, *args, **kwargs):
        try:
            user = User.objects.get(phone=request.data['phone'])
        except:
            return Response({'error': "User matching query doesn't exist"}, status=status.HTTP_404_NOT_FOUND)

        serializer = ResetPasswordSerializer(instance=user, data=request.data)
        if serializer.is_valid():
            ver = Verification.objects.get(phone=request.data['phone'])
            user.set_password(request.data['new_password'])
            ver.step_reset = ''
            ver.save()
            user.save()
            return Response({'message': 'Password successfully updated'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePhoneNumber(APIView):
    queryset = User.objects.all()
    serializer_class = PhoneSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(request_body=PhoneSerializer, tags=['Account'])
    def post(self, request, *args, **kwargs):
        phone = request.data.get("phone")
        if phone.isdigit() and len(phone) > 8:
            user = User.objects.filter(phone__iexact=phone)
            if user.exists():
                return Response({
                    "status": False,
                    "detail": "Bu raqam avval registerdan otgan."
                })
            else:
                otp = send_sms(phone)
                if 'verify_code' in otp:
                    code = str(otp['verify_code'])
                    try:
                        validate = ValidatedOtp.objects.get(phone=phone)
                        if validate.validated:
                            validate.otp = code
                            validate.validated = False
                            validate.save()
                        else:
                            pass

                    except ValidatedOtp.DoesNotExist as e:
                        phone = ValidatedOtp.objects.filter(phone__iexact=phone)
                        if not phone.exists():
                            ValidatedOtp.objects.create(phone=phone, otp=code, validated=False)
                        else:
                            Response({"number": "mavjud"})

                return Response({
                    "status": True,
                    "detail": "SMS xabarnoma jo'natildi",
                    "code": otp  # <--vaqtinchalik qo'shildi
                })
        else:
            if len(phone) < 8:
                return Response({"detail": "Telefon raqamingizni kod bilan kiriting!"})
            else:
                return Response({
                    "status": False,
                    "detail": "Telefon raqamni kiriting ."
                })

class ChangePhoneNumberVerifyCode(APIView):
    my_tags = ['Account']
    serializer_class = VerifyCodeSerializer
    permission_classes = [AllowAny]
    queryset = Verification.objects.all()

    @swagger_auto_schema(request_body=VerifyCodeSerializer, tags=['Account'])
    def put(self, request, *args, **kwargs):
        data = request.data
        try:
            obj = Verification.objects.get(phone=data['phone'])
            serializer = VerifyCodeSerializer(instance=obj, data=data)
            if serializer.is_valid():
                serializer.save()
                if serializer.data['step_change_phone'] == 'confirmed':
                    user = request.user
                    user.phone = data['phone']
                    user.save()
                    return Response({'message': 'Your phone number has been successfully changed!'},
                                status=status.HTTP_202_ACCEPTED)
                return Response({'message': 'This phone number has been successfully verified!'},
                                status=status.HTTP_202_ACCEPTED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Verification.DoesNotExist:
            return Response({'error': 'Phone number or verify code incorrect!'}, statusis_pupil=status.HTTP_400_BAD_REQUEST)

class ChangePhoneNumberConfirm(APIView):
    permission_classes = [AllowAny]
    serializer_class = PhoneSerializer

    @swagger_auto_schema(request_body=PhoneSerializer, tags=['Account'])
    def put(self, request, *args, **kwargs):
        try:
            user = User.objects.get(phone=request.user)
        except:
            return Response({'error': "User matching query doesn't exist"}, status=status.HTTP_404_NOT_FOUND)

        serializer = PhoneSerializer(instance=user, data=request.data)
        if serializer.is_valid():
            ver = Verification.objects.get(phone=request.data['phone'])
            user.phone = request.data['phone']
            user.save()
            ver.step_reset = ''
            ver.delete()

            updated_user = User.objects.get(phone=serializer.data['phone'])
            access_token = AccessToken().for_user(updated_user)
            refresh_token = RefreshToken().for_user(updated_user)

            return Response({'message': 'Phone successfully updated',
                            'access': str(access_token),
                            'refresh': str(refresh_token),
                            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


