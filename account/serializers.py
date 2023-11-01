from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from account.models import CustomUser
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
import re,uuid

reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
passObj = re.compile(reg)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = "__all__"


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = CustomUser.EMAIL_FIELD

    def validate(self, attrs):
        email = attrs.get("email", None)
        password = attrs.get("password", None)
        data = dict()
        try:
            user_instance = CustomUser.objects.get(email__iexact=email)
        except Exception as exception:
            data["status"] = status.HTTP_401_UNAUTHORIZED
            data['response'] = "User is not exists.Please Register first!"
            return data

        user = authenticate(email=email, password=password)
        if user is not None:
            refresh = self.get_token(user)
            data['status'] = status.HTTP_200_OK
            data['refresh'] = str(refresh)
            data['access'] = str(refresh.access_token)
            data['username'] = user.username.title()
            return data
        elif user is None:
            data['status'] = status.HTTP_401_UNAUTHORIZED
            data['response'] = "Incorrect Password!"
            return data
    @classmethod
    def get_token(cls, user):
        if user:
            token = super(MyTokenObtainPairSerializer, cls).get_token(user)
            token['username'] = user.username
            return token
        else:
            raise InvalidToken("User is not enabled.")


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=CustomUser.objects.all())]
            )
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    username = serializers.CharField(write_only=True, required=True)
    token = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ('username','first_name','last_name','password','email','token')

    def validate(self, attrs):
        pass_regex1 = re.search(passObj, attrs['password'])
        if not pass_regex1:
            raise serializers.ValidationError({"password": "Invalid Password!"})
        print(attrs)
        return attrs
        
    def create(self, validated_data):
        data = dict()
        get_uuid = uuid.uuid4()
        user = CustomUser.objects.create(
            username = validated_data['username'],
            email = validated_data['email'],
            first_name = validated_data['first_name'],
            last_name = validated_data['last_name']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

    def get_token(self,instance):
        try:
            refresh = RefreshToken.for_user(instance)
            token = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
            return token
        except Exception as e:
            return str(e)
        
    def to_representation(self,instance):
        try:
            data['status'] = status.HTTP_201_CREATED
            data['success'] = True
            data = super(RegisterSerializer,self).to_representation(instance)
            return data
        except Exception as exception:
            print(exception)
    



            
        