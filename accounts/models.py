import secrets
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from datetime import timedelta


class Role(models.TextChoices):
    SUPER_ADMIN = 'super_admin', 'Super Admin'
    ADMIN       = 'admin',       'Admin'
    UPLOADER    = 'uploader',    'Uploader'
    VIEWER      = 'viewer',      'Viewer'


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user  = self.model(email=email, **extra)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra):
        extra.setdefault('role',         Role.SUPER_ADMIN)
        extra.setdefault('is_staff',     True)
        extra.setdefault('is_superuser', True)
        extra.setdefault('is_active',    True)
        extra.setdefault('is_approved',  True)
        extra.setdefault('is_email_verified', True)
        return self.create_user(email, password, **extra)


class User(AbstractBaseUser, PermissionsMixin):
    email      = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100, blank=True)
    last_name  = models.CharField(max_length=100, blank=True)
    role       = models.CharField(max_length=20, choices=Role.choices, default=Role.VIEWER)

    # ── Zero Trust state ─────────────────────────────────────────────────────
    is_active         = models.BooleanField(default=False)   # activated only after email verify
    is_staff          = models.BooleanField(default=False)
    is_approved       = models.BooleanField(default=False)   # admin roles need super admin approval
    is_email_verified = models.BooleanField(default=False)   # email link clicked
    is_mfa_enabled    = models.BooleanField(default=False)

    # ── Login security (zero trust brute-force) ───────────────────────────────
    failed_login_attempts = models.PositiveSmallIntegerField(default=0)
    locked_until          = models.DateTimeField(null=True, blank=True)
    last_login_ip         = models.GenericIPAddressField(null=True, blank=True)
    last_user_agent       = models.CharField(max_length=300, blank=True)

    # ── Email verification token ──────────────────────────────────────────────
    email_verify_token    = models.CharField(max_length=64, blank=True)
    email_verify_sent_at  = models.DateTimeField(null=True, blank=True)

    # ── Email OTP (login step-2 for users without TOTP) ──────────────────────
    login_otp             = models.CharField(max_length=6, blank=True)
    login_otp_created_at  = models.DateTimeField(null=True, blank=True)
    login_otp_attempts    = models.PositiveSmallIntegerField(default=0)

    # ── Approval flow ─────────────────────────────────────────────────────────
    approval_requested_at = models.DateTimeField(null=True, blank=True)
    approved_by           = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.SET_NULL, related_name='approved_users',
    )
    approved_at = models.DateTimeField(null=True, blank=True)

    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD  = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-date_joined']

    def __str__(self):
        return f'{self.email} ({self.get_role_display()})'

    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'.strip() or self.email

    # ── Role helpers ──────────────────────────────────────────────────────────
    @property
    def is_super_admin(self): return self.role == Role.SUPER_ADMIN
    @property
    def is_admin(self):       return self.role in (Role.ADMIN, Role.SUPER_ADMIN)
    @property
    def is_uploader(self):    return self.role == Role.UPLOADER
    @property
    def is_viewer(self):      return self.role == Role.VIEWER

    @property
    def needs_approval(self):
        return self.role in (Role.ADMIN, Role.SUPER_ADMIN) and not self.is_approved

    def can_access(self):
        if not self.is_email_verified:
            return False
        if self.role in (Role.ADMIN, Role.SUPER_ADMIN):
            return self.is_approved
        return True

    # ── Account lockout ───────────────────────────────────────────────────────
    @property
    def is_locked(self):
        if self.locked_until and timezone.now() < self.locked_until:
            return True
        return False

    def record_failed_login(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 10:
            self.locked_until = timezone.now() + timedelta(hours=1)
        elif self.failed_login_attempts >= 5:
            self.locked_until = timezone.now() + timedelta(minutes=15)
        self.save(update_fields=['failed_login_attempts', 'locked_until'])

    def reset_failed_logins(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        self.save(update_fields=['failed_login_attempts', 'locked_until'])

    # ── Email verification token ───────────────────────────────────────────────
    def generate_email_verify_token(self):
        self.email_verify_token   = secrets.token_urlsafe(48)
        self.email_verify_sent_at = timezone.now()
        self.save(update_fields=['email_verify_token', 'email_verify_sent_at'])
        return self.email_verify_token

    @property
    def email_verify_token_valid(self):
        if not self.email_verify_sent_at:
            return False
        return timezone.now() < self.email_verify_sent_at + timedelta(hours=24)

    # ── Email OTP ─────────────────────────────────────────────────────────────
    def generate_login_otp(self):
        import random
        self.login_otp            = f'{random.randint(0, 999999):06d}'
        self.login_otp_created_at = timezone.now()
        self.login_otp_attempts   = 0
        self.save(update_fields=['login_otp', 'login_otp_created_at', 'login_otp_attempts'])
        return self.login_otp

    @property
    def login_otp_valid(self):
        if not self.login_otp_created_at:
            return False
        return timezone.now() < self.login_otp_created_at + timedelta(minutes=10)

    def verify_login_otp(self, code):
        """Returns True if code matches and is within time + attempt limits."""
        if self.login_otp_attempts >= 5:
            return False
        if not self.login_otp_valid:
            return False
        self.login_otp_attempts += 1
        self.save(update_fields=['login_otp_attempts'])
        if secrets.compare_digest(self.login_otp, code.strip()):
            self.login_otp = ''
            self.save(update_fields=['login_otp'])
            return True
        return False


class PendingRoleRequest(models.Model):
    user           = models.OneToOneField(User, on_delete=models.CASCADE, related_name='role_request')
    requested_role = models.CharField(max_length=20, choices=Role.choices)
    reason         = models.TextField(blank=True)
    status         = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected'),
    ], default='pending')
    created_at     = models.DateTimeField(auto_now_add=True)
    reviewed_by    = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='reviewed_requests')
    reviewed_at    = models.DateTimeField(null=True, blank=True)
    review_note    = models.TextField(blank=True)

    def __str__(self):
        return f'{self.user.email} → {self.requested_role} ({self.status})'
