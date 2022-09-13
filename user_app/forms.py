from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from django.contrib.auth import get_user_model


class CustomUserCreationForm(UserCreationForm):
    username: forms.Field = forms.CharField(
        label='Username', 
        min_length=5, 
        max_length=150
    )
    email: forms.Field = forms.EmailField(label="E-Mail")
    password1: forms.Field = forms.CharField(
        label='Password', 
        widget=forms.PasswordInput
    )
    password2: forms.Field = forms.CharField(
        label='Confirm Password', 
        widget=forms.PasswordInput
    )

    def clean_username(self):
        username = self.cleaned_data['username'].lower()
        new_user = User.objects.filter(username=username)
        if new_user.count():
            raise ValidationError("User already exists.")
        return username
    
    def clean_email(self):
        email = self.cleaned_data['email'].lower()
        new_email = User.objects.filter(email=email)
        if new_email.count():
            raise ValidationError("Email already exists.")
        return email
    
    def clean_password2(self) -> str:
        password1 = self.cleaned_data['password1']
        password2 = self.cleaned_data['password2']
        
        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords don't match")

        return password2
    
    def save(self, commit = True):
        user = User.objects.create_user(
            self.cleaned_data['username'],
            self.cleaned_data['email'],
            self.cleaned_data['password1']
        )
        return user





class RequestNewVerificationEmail(forms.Form):
    '''
    RequestNewVerificationEmail
    
    Form for requesting an email verification.
    '''
    email = forms.EmailField(
        label=get_user_model()._meta.get_field("email").verbose_name.capitalize(),  # noqa
        help_text=get_user_model()._meta.get_field("email").help_text.capitalize(),  # noqa
    )
