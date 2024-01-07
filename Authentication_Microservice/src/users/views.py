from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .utils import generate_otp, send_otp_phone,send_otp_email
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from users.models import UserModel
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_str
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import PasswordResetSerializer
from rest_framework import viewsets
from .permissions import CustomPermissions
from rest_framework import permissions
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from users.serializers import UserSerializer
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.views import PasswordResetConfirmView as BasePasswordResetConfirmView
from django.contrib.auth import get_user_model  
from django.utils.encoding import force_bytes
User = get_user_model()
    
class RegistrationView(viewsets.ModelViewSet):
    queryset = UserModel.objects.all()
    serializer_class = UserSerializer
    permission_classes=[CustomPermissions]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)

        to_email = request.data.get('email', '')
        otp = generate_otp() 
        user.otp = otp
        user.save()

        send_otp_email(to_email, otp)

        headers = self.get_success_headers(serializer.data)
        return Response({'message': 'User registered successfully. Check your email for OTP.'}, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        return serializer.save()


class LoginWithOTP(APIView):
    def post(self, request):
        phone_number = request.data.get('phone_number', '')
        try:
            user = UserModel.objects.get(phone_number=phone_number)
        except UserModel.DoesNotExist:
            return Response({'error': 'User with this Phone Number does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        otp = generate_otp()
        user.otp = otp
        user.save()
        send_otp_phone(phone_number, otp)

        return Response({'message': 'OTP has been sent to your Phone Number.'}, status=status.HTTP_200_OK)


class ValidateOTP(APIView):
    def post(self, request):
        if request.data.get('phone_number', ''):
            phone_number = request.data.get('phone_number', '')
            otp = request.data.get('otp', '')

            try:
                user = UserModel.objects.get(phone_number=phone_number)
            except UserModel.DoesNotExist:
                return Response({'error': 'User with this Phone Number does not exist.'}, status=status.HTTP_404_NOT_FOUND)

            if user.otp == otp:
                user.otp = None
                user.save()

                return Response({'massage': 'User LogIn Successfully.'},status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            email = request.data.get('email', '')
            otp = request.data.get('otp', '')

            try:
                user = UserModel.objects.get(email=email)
            except UserModel.DoesNotExist:
                return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

            if user.otp == otp:
                user.otp = None
                user.save()

                return Response({'massage': 'Email Verified Successful.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = UserModel.objects.get(email=email)
            except UserModel.DoesNotExist:
                return Response({'detail': 'User not found.'}, status=status.HTTP_400_BAD_REQUEST)

            token = default_token_generator.make_token(user)

            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = reverse('api:password_reset_confirm')

            subject = 'Password Reset'
            message = f'User uidb64: {uidb64},token: {token}'
            f'Click the following link to reset your password: {reset_link}'

            send_mail(subject, message, 'authentication@example.com', [email]) 

            return Response({'detail': 'Password reset email sent.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    def post(self, request):
        uidb64 = request.data.get('uidb64')
        token = request.data.get('token')
        password = request.data.get('password')

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))  # Change this line
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user and default_token_generator.check_token(user, token):
            user.set_password(password)
            user.save()

            return Response({'message': 'Password reset successful'})
        else:
            return Response({'message': 'Invalid token or user'}, status=status.HTTP_400_BAD_REQUEST)