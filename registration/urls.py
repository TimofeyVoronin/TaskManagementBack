from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegistrationAPIView,
    LoginAPIView,
    LogoutAPIView,
    PasswordResetRequestAPIView,
    PasswordResetConfirmAPIView,
    ChangePasswordAPIView,
)

urlpatterns = [
    path('signup/', RegistrationAPIView.as_view(), name='signup'),
    path('signin/', LoginAPIView.as_view(), name='signin'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Сброс пароля
    path('password-reset/', PasswordResetRequestAPIView.as_view(), name='password_reset_request'),
    path('password-reset/confirm/', PasswordResetConfirmAPIView.as_view(), name='password_reset_confirm'),

    # Смена пароля (пока залогинен)
    path('change-password/', ChangePasswordAPIView.as_view(), name='change_password'),
]