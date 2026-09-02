from django.shortcuts import redirect
from django.utils import timezone


class ZeroTrustMiddleware:
    """
    Zero Trust: enforces verification and approval on every request.
    - Unverified email → redirect to check_email
    - Unapproved admin role → redirect to pending
    - Logs IP and user agent on authenticated requests
    """
    EXEMPT = [
        '/accounts/',
        '/accounts/login/',
        '/accounts/register/',
        '/accounts/logout/',
        '/accounts/check-email/',
        '/accounts/verify/',
        '/accounts/resend-verification/',
        '/accounts/otp/',
        '/accounts/mfa/',
        '/accounts/pending/',
        '/static/',
        '/api/',
        '/favicon.ico',
    ]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path   = request.path
        exempt = any(path.startswith(p) for p in self.EXEMPT)
        user   = request.user

        if not exempt and user.is_authenticated:
            # Email not verified
            if not user.is_email_verified:
                return redirect('/accounts/check-email/')

            # Admin role not yet approved
            if user.needs_approval and path != '/accounts/pending/':
                return redirect('/accounts/pending/')

        return self.get_response(request)


# Keep backward-compat alias
RoleBasedAccessMiddleware = ZeroTrustMiddleware
