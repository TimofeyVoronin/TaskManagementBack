from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions as django_exceptions
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from drf_spectacular.utils import extend_schema_serializer, OpenApiExample

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str


@extend_schema_serializer(
    component_name='UserRegistration',
    examples=[
        OpenApiExample(
            'Register Request',
            summary='Запрос на регистрацию',
            value={
                'first_name': 'Иван',
                'last_name': 'Иванов',
                'email': 'ivan@example.com',
                'password': 'Str0ngP@ssw0rd'
            },
            request_only=True
        ),
        OpenApiExample(
            'Register Response',
            summary='Успешная регистрация',
            value={
                'id': 7,
                'first_name': 'Иван',
                'last_name': 'Иванов',
                'email': 'ivan@example.com'
            },
            response_only=True
        )
    ]
)
class CustomUserSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(
        required=True,
        help_text="Ваше имя"
    )
    last_name = serializers.CharField(
        required=True,
        help_text="Ваша фамилия"
    )
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())],
        help_text="Ваш email (он будет логином)"
    )
    password = serializers.CharField(
        write_only=True, required=True, min_length=8,
        help_text="Пароль минимум 8 символов"
    )

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'password')

    def validate_password(self, value):
        try:
            validate_password(value)
        except django_exceptions.ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def create(self, validated_data):
        first_name = validated_data.pop('first_name')
        last_name = validated_data.pop('last_name')
        email = validated_data.pop('email')
        password = validated_data.pop('password')

        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        return user


@extend_schema_serializer(
    component_name='Login',
    examples=[
        OpenApiExample(
            'Login Request',
            summary='Запрос на аутентификацию',
            value={'email': 'ivan@example.com', 'password': 'Str0ngP@ssw0rd'},
            request_only=True
        ),
    ]
)
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(help_text="Ваш email")
    password = serializers.CharField(write_only=True, help_text="Пароль")


@extend_schema_serializer(
    component_name='TokenPair',
    examples=[
        OpenApiExample(
            'TokenPair Response',
            summary='Пара JWT токенов',
            value={'refresh': '…', 'access': '…'},
            response_only=True
        ),
    ]
)
class TokenPairSerializer(serializers.Serializer):
    refresh = serializers.CharField(help_text="JWT refresh token")
    access = serializers.CharField(help_text="JWT access token")


@extend_schema_serializer(
    component_name='Logout',
    examples=[
        OpenApiExample(
            'Logout Request',
            summary='Запрос на выход',
            value={'refresh_token': '…'},
            request_only=True
        ),
        OpenApiExample(
            'Logout Response',
            summary='Успешный выход',
            value={'success': 'Выход выполнен'},
            response_only=True
        ),
    ]
)
class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(help_text="Refresh‑токен для чёрного списка")


@extend_schema_serializer(
    component_name='UserProfile',
    examples=[
        OpenApiExample(
            'Profile Response',
            summary='Данные профиля',
            value={
                'id': 7,
                'email': 'ivan@example.com',
                'first_name': 'Иван',
                'last_name': 'Иванов'
            },
            response_only=True
        ),
    ]
)
class ProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(read_only=True)
    first_name = serializers.CharField(required=False, allow_blank=True, help_text="Имя")
    last_name  = serializers.CharField(required=False, allow_blank=True, help_text="Фамилия")

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name')


@extend_schema_serializer(
    component_name='ChangePassword',
    examples=[
        OpenApiExample(
            'Change Password Request',
            summary='Запрос на смену пароля',
            value={'old_password': 'OldP@ss123', 'new_password': 'NewStr0ngP@ssw0rd'},
            request_only=True
        ),
        OpenApiExample(
            'Change Password Response',
            summary='Успешная смена пароля',
            value={'detail': 'Пароль успешно изменён'},
            response_only=True
        ),
    ]
)
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        write_only=True, help_text="Текущий пароль"
    )
    new_password = serializers.CharField(
        write_only=True, min_length=8, help_text="Новый пароль (мин. 8 символов)"
    )

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Текущий пароль указан неверно.")
        return value

    def validate_new_password(self, value):
        user = self.context['request'].user
        validate_password(value, user)
        return value

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(help_text="Email зарегистрированного пользователя")

    def validate_email(self, value):
        from django.contrib.auth.models import User
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Пользователь с таким email не найден.")
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField(help_text="UID из письма")
    token = serializers.CharField(help_text="Токен из письма")
    new_password = serializers.CharField(
        write_only=True, min_length=8,
        help_text="Новый пароль (мин. 8 символов)"
    )

    def validate(self, attrs):
        try:
            uid = force_str(urlsafe_base64_decode(attrs['uid']))
            from django.contrib.auth.models import User
            user = User.objects.get(pk=uid)
        except Exception:
            raise serializers.ValidationError("Неверный uid")

        token = attrs.get('token')
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Недействительный или просроченный токен")
        attrs['user'] = user
        return attrs