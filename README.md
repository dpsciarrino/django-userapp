# Project

## Getting Up and Running

### Setting Up the Virtual Environment

1. Run `python -m venv venv` to create the virtual environment.
2. Activate the virtual environment using `. venv/bin/activate` (don't forget the dot in front).
3. Install requirements with `pip install -r requirements.txt`.

4. At this point, you should define the required environment variables for the project. You can define them in an .env file and load them with the command below. See the Project Settings section for more information on the relevant environment variables.

```sh
export $(xargs < .env)
```

5. Django migrations: `python manage.py makemigrations` and `python manage.py migrate` in that order.

## Running Locally

Run the standard Django command `python manage.py runserver` to run the project locally.

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
```

You can also define them in environment variables and import them using:

```python
os.environ.get('KEY')
or
os.environ['KEY']
```

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

DEFAULT_FROM_EMAIL
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

