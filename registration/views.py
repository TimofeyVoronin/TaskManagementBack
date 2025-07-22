from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings

from rest_framework.views import APIView
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from drf_spectacular.utils import extend_schema, OpenApiResponse

from .serializers import (
    CustomUserSerializer,
    LoginSerializer,
    TokenPairSerializer,
    LogoutSerializer,
    ProfileSerializer,
    ChangePasswordSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
)


@extend_schema(
    request=CustomUserSerializer,
    responses={201: CustomUserSerializer},
    tags=['Auth']
)
class RegistrationAPIView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


@extend_schema(
    request=LoginSerializer,
    responses={200: TokenPairSerializer},
    tags=['Auth']
)
class LoginAPIView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = authenticate(username=email, password=password)

        if user is None:
            return Response(
                {'error': 'Неверные учётные данные'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        refresh = RefreshToken.for_user(user)
        tokens = {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
        return Response(tokens, status=status.HTTP_200_OK)


@extend_schema(
    request=LogoutSerializer,
    responses={200: OpenApiResponse(description="{'success': 'Выход выполнен'}")},
    tags=['Auth']
)
class LogoutAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            token = RefreshToken(serializer.validated_data['refresh_token'])
            token.blacklist()
        except Exception:
            return Response(
                {'error': 'Неверный refresh_token'},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response({'success': 'Выход выполнен'}, status=status.HTTP_200_OK)


@extend_schema(
    responses=ProfileSerializer,
    tags=['Auth']
)
class ProfileAPIView(generics.RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ProfileSerializer

    def get_object(self):
        return self.request.user


@extend_schema(
    request=ChangePasswordSerializer,
    responses={200: OpenApiResponse(description="{'detail': 'Пароль успешно изменён'}")},
    tags=['Auth']
)
class ChangePasswordAPIView(generics.UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.save()

        return Response(
            {"detail": "Пароль успешно изменён"},
            status=status.HTTP_200_OK
        )


@extend_schema(
    request=PasswordResetRequestSerializer,
    responses={200: OpenApiResponse(description="{'detail': 'Письмо отправлено'}")},
    tags=['Auth']
)
class PasswordResetRequestAPIView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = User.objects.get(email=email)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)

        reset_link = (
            f"{request.scheme}://{request.get_host()}"
            f"/profile/password-reset/confirm/?uid={uid}&token={token}"
        )

        send_mail(
            subject="Сброс пароля",
            message=f"Чтобы сбросить пароль, перейдите по ссылке:\n\n{reset_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )

        return Response({'detail': 'Письмо отправлено'}, status=status.HTTP_200_OK)


@extend_schema(
    request=PasswordResetConfirmSerializer,
    responses={200: OpenApiResponse(description="{'detail': 'Пароль успешно сброшен'}")},
    tags=['Auth']
)
class PasswordResetConfirmAPIView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        new_password = serializer.validated_data['new_password']
        user.set_password(new_password)
        user.save()

        return Response(
            {'detail': 'Пароль успешно сброшен'},
            status=status.HTTP_200_OK
        )
