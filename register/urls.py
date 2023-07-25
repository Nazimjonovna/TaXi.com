from django.urls import path
from .views import (Register, LogoutUserView,  OrderView, UserOrderView,
                    SendSms, PhoneView, OtpView, ChangePasswordView,
                    ResetPasswordView, ResetPasswordVerifyCode,
                    ResetPasswordConfirm, ChangePhoneNumber, ChangePhoneNumberVerifyCode,
                    ChangePhoneNumberConfirm, UserAccountView)

urlpatterns = [
    path('register', Register.as_view()),
    path('logout/', LogoutUserView.as_view()),
    path('acc/<int:pk>/', UserAccountView.as_view()),
    path('Order_user/', UserOrderView.as_view()),
    path('password/reset/', ResetPasswordView.as_view()),
    path('password/reset/verify/code/', ResetPasswordVerifyCode.as_view()),
    path('password/reset/confirm/', ResetPasswordConfirm.as_view()),
    path('phone/', PhoneView.as_view()),
    path('otp/', OtpView.as_view()),
    path('change_phone_number/', ChangePhoneNumber.as_view()),
    path('change_phone_number/verify/code/', ChangePhoneNumberVerifyCode.as_view()),
    path('change_phone_number/confirm/', ChangePhoneNumberConfirm.as_view()),
    path("send_sms/", SendSms.as_view()),
]