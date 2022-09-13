import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)

class UserAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'user_app'

    def ready(self):
        logger.info('[Email Verification] : importing signals    - OK.')
        import user_app.signals