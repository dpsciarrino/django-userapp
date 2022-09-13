# Django Basic User App

## Getting Up and Running

### Setting Up the Virtual Environment

1. Create a django project:

```sh
django-admin createproject <project-name>
```

2. Modify the ```settings.py``` file to include the following for setting up email and logging in:

```python
...
import os
...
########################## Login Configuration
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'index'

########################## SMTP Configuration
EMAIL_BACKEND = os.environ.get('EMAIL_BACKEND', '')
EMAIL_HOST = os.environ.get('EMAIL_HOST', '')
EMAIL_PORT = os.environ.get('EMAIL_PORT', '')
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', '')
```

3. Run migrations and create the superuser.

```sh
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

4. Edit the ```urls.py``` file so the new app URLs are included. For instance:

```python
urlpatterns = [
    path('user_app/', include('user_app.urls')),
    path('admin/', admin.site.urls),
]
```

5. Clone this repository. You'll need to massage the directory structure so that `user_app` folder is siblings with whatever the `<project-name>/<project-name>` folder is. Put the requirements.txt within the parent project folder.

6. Write an `.env` file for defining your email settings through environment variables. You can also hardcode them in `settings.py`, but only if this is going to be development and not deployed anywhere else!!!!!!!!!!!!!

7. Add ```user_app``` to the INSTALLED_APPS list in ```settings.py```.

```
INSTALLED_APPS = [
    'user_app',
    ...
]
```

8. Run `python -m venv venv` to create the virtual environment.

9. Activate the virtual environment using `. venv/bin/activate` (don't forget the dot in front).

10. Run the following command to load your environment variables from a .env file:

```sh
export $(xargs < .env) 
```

12. Install requirements with `pip install -r requirements.txt`.

13. Perform another migration: 
```sh
python manage.py makemigrations
python manage.py migrate
```

14. Run the app locally:

```
python manage.py runserver
```

## Project Settings

### General Email Settings

The variables that are associated with sending email are below and should be defined in the `settings.py` file.

```python
EMAIL_BACKEND
EMAIL_HOST
EMAIL_PORT
EMAIL_USE_TLS
EMAIL_HOST_USER
EMAIL_HOST_PASSWORD
DEFAULT_FROM_EMAIL
```

You can also define them in environment variables and import them using the command provided above.

You can find more information on configuring Django to send email here:
https://docs.djangoproject.com/en/4.1/topics/email/

### Email Verification Settings

The following variables all have default values stored in `userapp_configs.py`. You can override the default settings by defining their values in the `settings.py` file.

```python
REQUEST_NEW_EMAIL_TEMPLATE
NEW_EMAIL_SENT_TEMPLATE
LINK_EXPIRED_TEMPLATE

VERIFICATION_SUCCESS_TEMPLATE
VERIFICATION_FAILED_TEMPLATE
HTML_MESSAGE_TEMPLATE

VERIFICATION_FAILED_MSG 
VERIFICATION_SUCCESS_MSG
```

### Login Settings

The default settings for the login page and the login redirect are the 'login' and 'index' views, respectively. They are located in `settings.py`.

```python
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'index'
```

## User Login Functionality

The login functionality is a custom class-based view that extends `LoginView` from `django.contrib.auth.views`.

```python
user_app/urls.py

...
path('login/', CustomLoginView.as_view(), name='login'),
...
```

The default login page URL is set in `settings.py` using `LOGIN_URL`. This is used by the authentication backend.

The default redirect landing page on a successful login is set using `LOGIN_REDIRECT_URL`, also found in `settings.py`.

## Email Verification

The email verification on registration is adapted from the Django-Verify-Email repo authored by Nitin Sharma (foo290). This is a two-factor authentication procedure for the registration process via email.

https://github.com/foo290/Django-Verify-Email

## Password Reset Functionality

Password Reset is accomplished using four custom class-based views extending the following classes from the `django.contrib.auth.views`:
1. PasswordResetView
2. PasswordResetDoneView
3. PasswordResetConfirmView
4. PasswordResetCompleteView

More information can be found in the Django documentation:
https://docs.djangoproject.com/en/4.1/topics/auth/default/

