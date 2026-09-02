from django import forms
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.utils import timezone
from .models import User, Role, PendingRoleRequest
from .validators import validate_real_email


# ── Registration ───────────────────────────────────────────────────────────────

class RegisterForm(forms.ModelForm):
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'placeholder': 'Create a strong password', 'autocomplete': 'new-password'}),
        min_length=8,
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={'placeholder': 'Repeat your password', 'autocomplete': 'new-password'}),
    )

    ALLOWED_ROLES = [
        (Role.VIEWER,   'Viewer'),
        (Role.UPLOADER, 'Uploader'),
    ]
    role = forms.ChoiceField(choices=ALLOWED_ROLES, initial=Role.VIEWER)

    class Meta:
        model  = User
        fields = ['first_name', 'last_name', 'email', 'role']
        widgets = {
            'first_name': forms.TextInput(attrs={'placeholder': 'First name'}),
            'last_name':  forms.TextInput(attrs={'placeholder': 'Last name'}),
            'email':      forms.EmailInput(attrs={'placeholder': 'your@email.com', 'autocomplete': 'email'}),
        }

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()

        # ── Zero Trust: validate it's a real, deliverable email ──────────────
        try:
            validate_real_email(email)
        except ValidationError as e:
            raise e

        if User.objects.filter(email=email).exists():
            raise ValidationError('An account with this email already exists.')

        return email

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get('password1', '')
        p2 = cleaned.get('password2', '')
        if p1 and p2 and p1 != p2:
            self.add_error('password2', 'Passwords do not match.')

        # Basic password strength
        if p1:
            if p1.isdigit():
                self.add_error('password1', 'Password cannot be entirely numeric.')
            if len(p1) < 8:
                self.add_error('password1', 'Password must be at least 8 characters.')

        return cleaned

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        user.is_active         = False   # blocked until email verified
        user.is_email_verified = False
        user.is_approved       = True    # viewer/uploader don't need admin approval
        if commit:
            user.save()
        return user


# ── Login ──────────────────────────────────────────────────────────────────────

class LoginForm(forms.Form):
    LOGIN_ROLE_CHOICES = [
        ('viewer',   'Viewer'),
        ('uploader', 'Uploader'),
        ('admin',    'Admin'),
    ]

    email    = forms.EmailField(widget=forms.EmailInput(attrs={'placeholder': 'Email address', 'autocomplete': 'email'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Password', 'autocomplete': 'current-password'}))
    login_as = forms.ChoiceField(choices=LOGIN_ROLE_CHOICES, initial='viewer')

    def __init__(self, request=None, *args, **kwargs):
        self.request    = request
        self.user_cache = None
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned  = super().clean()
        email    = cleaned.get('email', '').strip().lower()
        password = cleaned.get('password', '')
        login_as = cleaned.get('login_as', '')

        if not email or not password:
            return cleaned

        # ── Zero Trust: validate email is syntactically valid before DB lookup ─
        from .validators import validate_email_syntax
        try:
            validate_email_syntax(email)
        except ValidationError:
            raise ValidationError('Enter a valid email address.')

        # ── Check lockout before authenticating ────────────────────────────────
        try:
            user_obj = User.objects.get(email=email)
            if user_obj.is_locked:
                mins = int((user_obj.locked_until - timezone.now()).total_seconds() / 60) + 1
                raise ValidationError(
                    f'Account temporarily locked due to too many failed attempts. '
                    f'Try again in {mins} minute(s).'
                )
        except User.DoesNotExist:
            # Don't reveal whether the email exists — generic error below
            pass

        # ── Authenticate ───────────────────────────────────────────────────────
        self.user_cache = authenticate(self.request, username=email, password=password)

        if self.user_cache is None:
            # Record failed attempt if user exists
            try:
                u = User.objects.get(email=email)
                u.record_failed_login()
            except User.DoesNotExist:
                pass
            raise ValidationError('Invalid email or password.')

        # ── Email must be verified ─────────────────────────────────────────────
        if not self.user_cache.is_email_verified:
            raise ValidationError(
                'Please verify your email address before logging in. '
                'Check your inbox for the verification link.'
            )

        if not self.user_cache.is_active:
            raise ValidationError('This account has been disabled.')

        # ── Role check ─────────────────────────────────────────────────────────
        role = self.user_cache.role
        if login_as == 'admin' and role not in (Role.ADMIN, Role.SUPER_ADMIN):
            raise ValidationError('You do not have admin access.')
        if login_as == 'uploader' and role != Role.UPLOADER:
            raise ValidationError('Your account is not registered as an Uploader.')
        if login_as == 'viewer' and role not in (Role.VIEWER,):
            raise ValidationError('Your account is not registered as a Viewer.')

        # ── Approval check for restricted roles ────────────────────────────────
        if not self.user_cache.can_access():
            raise ValidationError(
                'Your admin account is pending Super Admin approval. '
                'You will be notified by email once approved.'
            )

        # ── Success: reset failed attempts ─────────────────────────────────────
        self.user_cache.reset_failed_logins()
        return cleaned

    def get_user(self):
        return self.user_cache


# ── Email OTP verify (login step 2) ───────────────────────────────────────────

class EmailOTPForm(forms.Form):
    otp = forms.CharField(
        max_length=6, min_length=6,
        widget=forms.TextInput(attrs={
            'placeholder': '000000',
            'inputmode': 'numeric',
            'pattern': '[0-9]{6}',
            'autocomplete': 'one-time-code',
        }),
        label='6-digit code',
    )


# ── TOTP MFA verify ───────────────────────────────────────────────────────────

class MFAVerifyForm(forms.Form):
    token = forms.CharField(
        max_length=6, min_length=6,
        widget=forms.TextInput(attrs={
            'placeholder': '000000',
            'inputmode': 'numeric',
            'pattern': '[0-9]{6}',
            'autocomplete': 'one-time-code',
        }),
        label='Authenticator code',
    )


class MFASetupForm(forms.Form):
    confirm_token = forms.CharField(
        max_length=6, min_length=6,
        widget=forms.TextInput(attrs={
            'placeholder': 'Enter code from your authenticator app',
            'inputmode': 'numeric',
            'pattern': '[0-9]{6}',
        }),
    )


# ── Role request ───────────────────────────────────────────────────────────────

class RoleRequestForm(forms.ModelForm):
    requested_role = forms.ChoiceField(choices=[
        (Role.ADMIN,       'Admin'),
        (Role.SUPER_ADMIN, 'Super Admin'),
    ])

    class Meta:
        model  = PendingRoleRequest
        fields = ['requested_role', 'reason']
        widgets = {'reason': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Explain why you need this role...'})}


class ReviewRoleRequestForm(forms.Form):
    action      = forms.ChoiceField(choices=[('approved', 'Approve'), ('rejected', 'Reject')])
    review_note = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 2, 'placeholder': 'Optional note'}),
        required=False,
    )
