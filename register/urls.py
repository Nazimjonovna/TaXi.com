from django.urls import path
from .views import (Register, LogoutUserView, DriverAcc, OrderView, UserOrderView,
                    SendSms, PhoneView, OtpView, ChangePasswordView,
                    ResetPasswordView, ResetPasswordVerifyCode,
                    ResetPasswordConfirm, ChangePhoneNumber, ChangePhoneNumberVerifyCode,
                    ChangePhoneNumberConfirm)
    # DriverOrderView, UserOrderView, OrderView

urlpatterns = [
    path('register', Register.as_view()),
    path('logout/', LogoutUserView.as_view()),
    path('Account/<int:pk>/', DriverAcc.as_view()),
    path("Order_driver/<int:pk>/", OrderView.as_view()),
    path('Order_user/', UserOrderView.as_view()),
    path('change_password/<int:pk>/', ChangePasswordView.as_view(), name='auth_change_password'),
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