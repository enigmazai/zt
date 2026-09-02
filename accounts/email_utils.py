"""
Zero Trust email helpers.
Sends verification links and OTP codes via Django's email backend.
"""
from django.core.mail import send_mail
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings
from django.urls import reverse
import logging

logger = logging.getLogger(__name__)


def send_verification_email(user, request):
    """Send email verification link after signup."""
    token = user.generate_email_verify_token()
    verify_url = request.build_absolute_uri(
        reverse('accounts:verify_email', args=[token])
    )
    subject = 'Verify your MediaPlatform email address'
    body = f"""Hi {user.first_name or user.email},

Welcome to MediaPlatform! Please verify your email address to activate your account.

Click the link below (valid for 24 hours):

  {verify_url}

If you did not create an account, you can safely ignore this email.

— The MediaPlatform Team
"""
    send_mail(
        subject,
        body,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )
    # Helpful dev/logging: record the verification url in logs when DEBUG
    try:
        logger.info('Verification email sent to %s; link=%s',
                    user.email, verify_url)
    except Exception:
        pass
    return verify_url


def send_login_otp(user):
    """Send a 6-digit OTP code for email-based login verification."""
    if (settings.EMAIL_BACKEND == 'django.core.mail.backends.smtp.EmailBackend'
            and (not settings.EMAIL_HOST_USER or not settings.EMAIL_HOST_PASSWORD)):
        raise ImproperlyConfigured(
            'SMTP email delivery requires EMAIL_HOST_USER and EMAIL_HOST_PASSWORD.')

    otp = user.generate_login_otp()
    subject = f'Your MediaPlatform login code: {otp}'
    body = f"""Hi {user.first_name or user.email},

Your one-time login verification code is:

    {otp}

This code expires in 10 minutes. Do not share it with anyone.

If you did not attempt to log in, please change your password immediately.

— The MediaPlatform Security Team
"""
    send_mail(
        subject,
        body,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )
    logger.info('Login OTP email sent to %s', user.email)


def send_resend_verification(user, request):
    """Re-send verification email (rate-limited in the view)."""
    send_verification_email(user, request)


def notify_superadmins(subject, message):
    from .models import User, Role
    admins = User.objects.filter(role=Role.SUPER_ADMIN, is_active=True)
    emails = list(admins.values_list('email', flat=True))
    if emails:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL,
                  emails, fail_silently=True)


def send_role_approved(user, role):
    send_mail(
        'Your MediaPlatform role has been approved',
        f'Hi {user.first_name or user.email},\n\n'
        f'Your request for the {role} role has been approved. '
        f'You can now log in with elevated access.\n\n'
        f'— MediaPlatform',
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=True,
    )


def send_role_rejected(user, role, note=''):
    send_mail(
        'MediaPlatform role request update',
        f'Hi {user.first_name or user.email},\n\n'
        f'Your request for the {role} role was not approved.\n'
        f'{"Reviewer note: " + note if note else ""}\n\n'
        f'— MediaPlatform',
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=True,
    )
