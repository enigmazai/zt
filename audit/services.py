"""
Audit logging service — a thin, dependency-free helper for recording
security-sensitive actions across the platform.
"""
from django.contrib.contenttypes.models import ContentType

from .models import AuditLog


def _get_client_ip(request):
    """Extract the real client IP, respecting proxies."""
    if request is None:
        return None
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def _get_user_agent(request):
    if request is None:
        return ''
    return request.META.get('HTTP_USER_AGENT', '')[:500]


def _get_path(request):
    if request is None:
        return ''
    return request.get_full_path()[:500]


def _get_method(request):
    if request is None:
        return ''
    return request.method or ''


def _model_to_dict(obj, fields=None):
    """Serialize a model instance to a JSON-safe dict, excluding sensitive fields."""
    if obj is None:
        return {}
    exclude = {'password', 'login_otp', 'email_verify_token'}
    data = {}
    for field in obj._meta.fields:
        name = field.name
        if name in exclude:
            continue
        if fields and name not in fields:
            continue
        value = getattr(obj, name)
        # Datetimes/dates -> ISO
        if hasattr(value, 'isoformat'):
            value = value.isoformat()
        # File fields / cloud fields -> string path/url
        elif hasattr(value, 'url'):
            value = str(value)
        # Related model instances (ForeignKey) -> use PK for JSON safety
        elif hasattr(value, '_meta'):
            try:
                value = value.pk
            except Exception:
                value = str(value)
        # Fallback: convert non-serializable types to str
        try:
            # attempt simple JSON-friendly conversions for common types
            if isinstance(value, (bytes, bytearray)):
                value = value.decode('utf-8', errors='ignore')
        except Exception:
            value = str(value)
        data[name] = value
    return data


def audit_log(
    *,
    action,
    user=None,
    request=None,
    description='',
    category='',
    obj=None,
    before=None,
    after=None,
    fields=None,
):
    """
    Record an audit log entry.

    Args:
        action:      AuditLog.Action value (string)
        user:        User instance or None (anonymous)
        request:     HttpRequest for IP / UA / path / method
        description: Human-readable summary
        category:    'auth', 'media', 'role', 'security', etc.
        obj:         Model instance the action relates to (optional)
        before:      dict of pre-change state (optional)
        after:       dict of post-change state (optional)
        fields:      if provided, only these model fields are serialized
    """
    if before is None and obj is not None:
        before = _model_to_dict(obj, fields=fields)
    if after is None and obj is not None:
        after = _model_to_dict(obj, fields=fields)

    content_type = None
    object_id = None
    if obj is not None:
        content_type = ContentType.objects.get_for_model(obj)
        object_id = obj.pk

    return AuditLog.objects.create(
        user=user if (user and user.is_authenticated) else None,
        user_email=(user.email if user and user.is_authenticated else ''),
        action=action,
        category=category,
        description=description,
        content_type=content_type,
        object_id=object_id,
        before=before or {},
        after=after or {},
        ip_address=_get_client_ip(request),
        user_agent=_get_user_agent(request),
        path=_get_path(request),
        method=_get_method(request),
    )


def audit_model_change(action, instance, request=None, fields=None, description=''):
    """
    Convenience wrapper: captures before/after state of a model instance
    and logs the change.
    """
    before = _model_to_dict(instance, fields=fields)
    return audit_log(
        action=action,
        user=getattr(request, 'user', None) if request else None,
        request=request,
        description=description or f'{instance.__class__.__name__} changed',
        category=instance.__class__.__name__.lower(),
        obj=instance,
        before=before,
        after=_model_to_dict(instance, fields=fields),
    )
