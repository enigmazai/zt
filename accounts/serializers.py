from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Adds role, email, full_name, mfa_enabled to JWT payload."""

    username_field = 'email'

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['email']       = user.email
        token['role']        = user.role
        token['full_name']   = user.full_name
        token['mfa_enabled'] = user.is_mfa_enabled
        return token

    def validate(self, attrs):
        # simplejwt uses username_field; map email → username
        data = super().validate(attrs)
        user = self.user
        data['user'] = {
            'id':          user.pk,
            'email':       user.email,
            'full_name':   user.full_name,
            'role':        user.role,
            'mfa_enabled': user.is_mfa_enabled,
        }
        return data


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model  = User
        fields = ['id', 'email', 'first_name', 'last_name', 'role', 'is_mfa_enabled', 'date_joined']
        read_only_fields = ['id', 'role', 'date_joined']
