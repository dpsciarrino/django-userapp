from django.urls import path
from django.contrib.auth.views import LogoutView

# Placeholder
from .views import index

# Login
from .views import CustomLoginView

# Registration
from .views import CustomRegisterView
from .views import verify_user_and_activate, request_new_link

# Password Reset
from .views import CustomPasswordResetCompleteView
from .views import CustomPasswordResetConfirmView
from .views import CustomPasswordResetDoneView
from .views import CustomPasswordResetView

from .userapp_configs import GetFieldFromSettings
pkg_configs = GetFieldFromSettings()

urlpatterns = [
    path('', index, name='index'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('register/', CustomRegisterView.as_view(), name='register'),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    # Password Reset
    path(
        'password-reset/',
        CustomPasswordResetView.as_view(),
        name='reset_password'
        ),
    path(
        'password-reset-sent/',
        CustomPasswordResetDoneView.as_view(),
        name='password_reset_done'
        ),
    path(
        'password-reset-confirm/<uidb64>/<token>/',
        CustomPasswordResetConfirmView.as_view(),
        name='password_reset_confirm'
        ),
    path(
        'password-reset-complete/',
        CustomPasswordResetCompleteView.as_view(),
        name='password_reset_complete'
        ),
    # Registration E-mail Verification
    path(f'verify-email/<useremail>/<usertoken>/', verify_user_and_activate, name='verify-email'),
    path(f'verify-email/request-new-link/<useremail>/<usertoken>/', request_new_link, name='request-new-link-from-token'),
    path(f'verify-email/request-new-link/', request_new_link, name='request-new-link-from-email'),
]