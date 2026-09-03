#!/usr/bin/env bash
set -o errexit

python manage.py migrate --no-input
python manage.py collectstatic --no-input

if [ -n "${DJANGO_SUPERUSER_EMAIL:-}" ] && [ -n "${DJANGO_SUPERUSER_PASSWORD:-}" ]; then
python manage.py shell <<'PY'
import os

from accounts.models import Role, User

email = os.environ['DJANGO_SUPERUSER_EMAIL'].strip().lower()
password = os.environ['DJANGO_SUPERUSER_PASSWORD']
user, created = User.objects.get_or_create(email=email)
user.role = Role.SUPER_ADMIN
user.is_staff = True
user.is_superuser = True
user.is_active = True
user.is_approved = True
user.is_email_verified = True
user.set_password(password)
user.save()
print(f"{'Created' if created else 'Updated'} superuser: {email}")
PY
fi