from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.contrib.auth.views import PasswordResetView
from django.contrib.auth.views import PasswordResetDoneView
from django.contrib.auth.views import PasswordResetConfirmView
from django.contrib.auth.views import PasswordResetCompleteView
from django.core.signing import SignatureExpired, BadSignature
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect
from django.urls import reverse_lazy, reverse
from django.views.generic import FormView

import logging

from .forms import CustomUserCreationForm, RequestNewVerificationEmail

from .userapp_configs import GetFieldFromSettings
from .userapp_errors import UserAlreadyActive, MaxRetriesExceeded, UserNotFound, InvalidToken
from .userapp_util import send_verification_email, resend_verification_email
from .userapp_util import verify_user

logger = logging.getLogger(__name__)

@login_required
def index(request):
    """
    Welcome page after successful login.
    """
    return render(request, 'user_app/index.html', {})

class CustomLoginView(LoginView):
    """
    CustomLoginView

    Login Page
    """
    template_name = 'user_app/login.html'
    fields = '__all__'
    redirect_authenticated_user = True
    #success_url = reverse_lazy('index')

    #def get_success_url(self):
    #    return reverse_lazy('index')

class CustomRegisterView(FormView):
    """
    CustomRegisterView
    """
    template_name = 'user_app/register.html'
    form_class = CustomUserCreationForm
    redirect_authenticated_user = True
    success_url = reverse_lazy('request-new-link-from-email')

    def form_valid(self, form):
        # This method is called when valid form data is posted.
        # It should return an HTTP response
        inactive_user = send_verification_email(self.request, form)

        return super().form_valid(form)
    
    def form_invalid(self, form):
        return super().form_invalid(form)


    def get(self, *args, **kwargs):
        if(self.request.user.is_authenticated):
            return redirect('index')
            
        return super(CustomRegisterView, self).get(*args, **kwargs)

class CustomPasswordResetView(PasswordResetView):
    '''
    CustomPasswordResetView

    Page displayed with an email field for initializing a password reset request.
    '''
    template_name="user_app/password_reset.html"

class CustomPasswordResetDoneView(PasswordResetDoneView):
    '''
    CustomPasswordResetDoneView

    Page displayed after making a password reset request. Email is sent, waiting for user to activate link.
    '''
    template_name="user_app/password_reset_done.html"
    
    def get(self, *args, **kwargs):
        if(self.request.user.is_authenticated):
            return redirect('index')
            
        return super(CustomPasswordResetDoneView, self).get(*args, **kwargs)

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    '''
    CustomPasswordResetConfirmView

    User has clicked the link sent via email, page displays fields for password and password confirmation.
    '''
    template_name="user_app/password_reset_confirm.html"

class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    '''
    CustomPasswordResetCompletedView

    User has successfully changed their password.
    '''
    template_name="user_app/password_reset_complete.html"

    def get(self, *args, **kwargs):
        if(self.request.user.is_authenticated):
            return redirect('index')
            
        return super(CustomPasswordResetCompleteView, self).get(*args, **kwargs)



# Settings for verification functions:
pkg_configs = GetFieldFromSettings()
login_page = pkg_configs.get('login_page')
success_msg = pkg_configs.get('verification_success_msg')
failed_msg = pkg_configs.get('verification_failed_msg')
failed_template = pkg_configs.get('verification_failed_template')
success_template = pkg_configs.get('verification_success_template')
link_expired_template = pkg_configs.get('link_expired_template')

def verify_user_and_activate(request, useremail, usertoken):
    '''
    verify_user_and_activate

    Handles resulting logic of user verification after user visits tokenized link.
    '''
    try:
        verified = verify_user(useremail, usertoken)
        if verified is True:
            if login_page and not success_template:
                messages.success(request, success_msg)
                return redirect(to=login_page)
            return render(
                request,
                template_name=success_template,
                context={
                    'msg': success_msg,
                    'status': 'Verification Successful!',
                    'link': reverse(login_page)
                }
            )
        else:
            # we dont know what went wrong...
            raise ValueError
    except (ValueError, TypeError) as error:
        logger.error(f'[ERROR]: Something went wrong while verifying user, exception: {error}')
        return render(
            request,
            template_name=failed_template,
            context={
                'msg': failed_msg,
                'minor_msg': 'There is something wrong with this link...',
                'status': 'Verification Failed!',
            }
        )
    except SignatureExpired:
        return render(
            request,
            template_name=link_expired_template,
            context={
                'msg': 'The link has lived its life :( Request a new one!',
                'status': 'Expired!',
                'encoded_email': useremail,
                'encoded_token': usertoken
            }
        )
    except BadSignature:
        return render(
            request,
            template_name=failed_template,
            context={
                'msg': 'This link was modified before verification.',
                'minor_msg': 'Cannot request another verification link with faulty link.',
                'status': 'Faulty Link Detected!',
            }
        )
    except MaxRetriesExceeded:
        return render(
            request,
            template_name=failed_template,
            context={
                'msg': 'You have exceeded the maximum verification requests! Contact admin.',
                'status': 'Maxed out!',
            }
        )
    except InvalidToken:
        return render(
            request,
            template_name=failed_template,
            context={
                'msg': 'This link is invalid or been used already, we cannot verify using this link.',
                'status': 'Invalid Link',
            }
        )
    except UserNotFound:
        raise Http404("404 User not found")



new_email_sent_template = pkg_configs.get('new_email_sent_template')
request_new_email_template = pkg_configs.get('request_new_email_template')

def request_new_link(request, useremail=None, usertoken=None):
    '''
    request_new_link

    Used to evaluate user requests for mailed verification links.
    '''
    try:
        if useremail is None or usertoken is None:
            # request came from re-request email page
            if request.method == 'POST':
                form = RequestNewVerificationEmail(request.POST)  # do not inflate data
                if form.is_valid():
                    form_data: dict = form.cleaned_data
                    email = form_data['email']

                    inactive_user = get_user_model().objects.get(email=email)
                    if inactive_user.is_active:
                        raise UserAlreadyActive('User is already active')
                    else:
                        # resend email
                        status = resend_verification_email(request, email, user=inactive_user, encoded=False)
                        if status:
                            return render(
                                request,
                                template_name=new_email_sent_template,
                                context={
                                    'msg': "You have requested another verification email!",
                                    'minor_msg': 'Your verification link has been sent.',
                                    'status': 'Email Sent!',
                                }
                            )
                        else:
                            logger.error('something went wrong during sending email')
            else:
                form = RequestNewVerificationEmail()
            return render(
                request,
                template_name=request_new_email_template,
                context={'form': form}
            )
        else:
            # request came from  previously sent link
            status = resend_verification_email(request, useremail, token=usertoken)

        if status:
            return render(
                request,
                template_name=new_email_sent_template,
                context={
                    'msg': "You've requested another verification link!",
                    'minor_msg': 'An email with the verification link has been sent.',
                    'status': 'Rerequest Sent!',
                }
            )
        else:
            messages.info(request, 'Something went wrong during sending email :(')
            logger.error('something went wrong during sending email')

    except ObjectDoesNotExist as error:
        messages.warning(request, 'No user was found with the given email address.')
        logger.error(f'[ERROR]: User not found. Exception: {error}')
        return render(
                request,
                template_name=request_new_email_template,
                context={'form': form})

    except MultipleObjectsReturned as error:
        logger.error(f'[ERROR]: Multiple users found. Exception: {error}')
        return HttpResponse(b"Internal server error!", status=500)

    except KeyError as error:
        logger.error(f'[ERROR]: Key error for email in your form: {error}')
        return HttpResponse(b"Internal server error!", status=500)

    except MaxRetriesExceeded as error:
        logger.error(f'[ERROR]: Maximum retries for link has been reached. Exception: {error}')
        return render(
            request,
            template_name=failed_template,
            context={
                'msg': 'You have exceeded the maximum verification requests. Please contact the administrator.',
                'status': 'Maxed out number of verification requests!',
            }
        )
    except InvalidToken:
        return render(
            request,
            template_name=failed_template,
            context={
                'msg': 'This link is invalid or has already been used.',
                'status': 'Invalid Link',
            }
        )
    except UserAlreadyActive:
        return render(
            request,
            template_name=failed_template,
            context={
                'msg': "This user's account is already active",
                'status': 'Already Verified!',
            }
        )