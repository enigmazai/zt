from django.conf import settings
import django
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Media_platform.settings')
django.setup()
print('DEBUG=', settings.DEBUG)
print('ALLOWED_HOSTS=', settings.ALLOWED_HOSTS)
print('SECURE_SSL_REDIRECT=', getattr(settings, 'SECURE_SSL_REDIRECT', None))
