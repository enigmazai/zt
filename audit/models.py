from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models


class AuditLog(models.Model):
    """
    Immutable audit trail for security-sensitive actions.
    Records who did what, when, from where, and the before/after state.
    """

    class Action(models.TextChoices):
        # ── Authentication & account ──────────────────────────────────────
        REGISTER            = 'register',            'User Registered'
        EMAIL_VERIFIED      = 'email_verified',      'Email Verified'
        LOGIN_SUCCESS       = 'login_success',       'Login Successful'
        LOGIN_FAILED        = 'login_failed',        'Login Failed'
        LOGIN_OTP_SENT      = 'login_otp_sent',      'Login OTP Sent'
        LOGIN_OTP_VERIFIED  = 'login_otp_verified',  'Login OTP Verified'
        LOGIN_OTP_FAILED    = 'login_otp_failed',    'Login OTP Failed'
        MFA_VERIFIED        = 'mfa_verified',        'MFA Verified'
        MFA_SETUP           = 'mfa_setup',           'MFA Enabled'
        MFA_DISABLED        = 'mfa_disabled',        'MFA Disabled'
        LOGOUT              = 'logout',              'User Logged Out'
        ACCOUNT_LOCKED      = 'account_locked',      'Account Locked'
        PASSWORD_CHANGED    = 'password_changed',    'Password Changed'

        # ── Role & approval ───────────────────────────────────────────────
        ROLE_REQUESTED      = 'role_requested',      'Role Requested'
        ROLE_APPROVED       = 'role_approved',       'Role Approved'
        ROLE_REJECTED       = 'role_rejected',       'Role Rejected'
        USER_APPROVED       = 'user_approved',       'User Approved'

        # ── Media ─────────────────────────────────────────────────────────
        MEDIA_UPLOADED      = 'media_uploaded',      'Media Uploaded'
        MEDIA_UPDATED       = 'media_updated',       'Media Updated'
        MEDIA_DELETED       = 'media_deleted',       'Media Deleted'
        MEDIA_PUBLISHED     = 'media_published',     'Media Published'
        MEDIA_VIEWED        = 'media_viewed',        'Media Viewed'
        MEDIA_DOWNLOADED    = 'media_downloaded',    'Media Downloaded'

        # ── Security ──────────────────────────────────────────────────────
        PERMISSION_DENIED   = 'permission_denied',   'Permission Denied'
        RATE_LIMITED        = 'rate_limited',        'Rate Limited'
        SUSPICIOUS_ACTIVITY = 'suspicious_activity', 'Suspicious Activity'

    # Who
    user        = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='audit_logs',
    )
    user_email  = models.CharField(max_length=255, blank=True)  # snapshot in case user is deleted

    # What
    action      = models.CharField(max_length=50, choices=Action.choices)
    category    = models.CharField(max_length=50, blank=True)  # e.g. 'auth', 'media', 'role'
    description = models.TextField(blank=True)

    # Object affected (generic FK)
    content_type = models.ForeignKey(ContentType, null=True, blank=True, on_delete=models.SET_NULL)
    object_id    = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')

    # Before / after state (JSON)
    before      = models.JSONField(default=dict, blank=True)
    after       = models.JSONField(default=dict, blank=True)

    # Where
    ip_address  = models.GenericIPAddressField(null=True, blank=True)
    user_agent  = models.CharField(max_length=500, blank=True)
    path        = models.CharField(max_length=500, blank=True)
    method      = models.CharField(max_length=10, blank=True)

    # When
    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['action', '-created_at']),
            models.Index(fields=['content_type', 'object_id']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        who = self.user_email or self.user or 'anonymous'
        return f'{self.created_at:%Y-%m-%d %H:%M} | {who} | {self.get_action_display()}'