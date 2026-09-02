from django.test import Client
import django
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Media_platform.settings')
django.setup()
c = Client()
r = c.get('/')
print('status_code=', r.status_code)
payload = r.content.decode(errors='replace')
print('content_snippet=', payload[:200].replace('\n', '\\n'))
