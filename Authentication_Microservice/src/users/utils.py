import random
import string
from django.conf import settings
from twilio.rest import Client
from django.core.mail import send_mail

def generate_otp(length=6):
    characters = string.digits
    otp = ''.join(random.choice(characters) for _ in range(length))
    return otp

def send_otp_phone(phone_number, otp):
    account_sid = 'ACbe22a1cdd9bc3412f6645f6842fc314b'  
    auth_token = 'a10b289ae3533c7b26fcb59a19d3cf1e'
    twilio_phone_number = '+14846601334' 

    client = Client(account_sid, auth_token)
    message = client.messages.create(
        body=f'Your OTP is: {otp}',
        from_=twilio_phone_number,
        to=phone_number
    )

def send_otp_email(email, otp):
    subject = 'Your OTP for Email Verification'
    message = f'Your OTP is: {otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)