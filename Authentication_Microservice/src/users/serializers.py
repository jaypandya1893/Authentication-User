from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from users.models import UserModel
from rest_framework import serializers
from users.models import UserModel

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = ['id','role', 'username', 'first_name', 'last_name', 'email', 'phone_number', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
            'username': {
                'validators': [UniqueValidator(queryset=UserModel.objects.all())],
                'required': False,
            }
        }

    def create(self, validated_data):
        suggested_username = f"{validated_data['phone_number']}"

        if UserModel.objects.filter(username=suggested_username).exists():
            raise serializers.ValidationError({'username': ['This username already exists.']})

        validated_data['username'] = suggested_username
        user = UserModel.objects.create_user(**validated_data)
        return user
    
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()