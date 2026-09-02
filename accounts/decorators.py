from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from django.http import HttpResponseForbidden


def role_required(*roles):
    """
    Decorator for views requiring specific roles.
    Usage: @role_required('admin', 'super_admin')
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('accounts:auth')
            if request.user.role not in roles:
                messages.error(request, 'You do not have permission to access this page.')
                return HttpResponseForbidden(
                    '<h1>403 Forbidden</h1><p>Insufficient permissions.</p>'
                )
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def approved_only(view_func):
    """Redirect unapproved restricted-role users."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.needs_approval:
            messages.warning(request, 'Your account is pending approval.')
            return redirect('accounts:pending_approval')
        return view_func(request, *args, **kwargs)
    return wrapper


class RoleBasedAccessMiddleware:
    """
    Global middleware that blocks unapproved admin/super_admin
    accounts from accessing any page except the auth/logout pages.
    """
    EXEMPT_PATHS = [
        '/accounts/login/',
        '/accounts/register/',
        '/accounts/logout/',
        '/accounts/auth/',
        '/accounts/pending/',
        '/static/',
        '/favicon.ico',
    ]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        exempt = any(path.startswith(p) for p in self.EXEMPT_PATHS)

        if (not exempt
                and request.user.is_authenticated
                and request.user.needs_approval
                and path != '/accounts/pending/'):
            return redirect('/accounts/pending/')

        return self.get_response(request)
