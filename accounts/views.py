import io
import logging
import qrcode
import qrcode.image.svg

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import Http404

from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp import match_token

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status as drf_status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .forms import (
    RegisterForm, LoginForm, EmailOTPForm,
    MFAVerifyForm, MFASetupForm, RoleRequestForm, ReviewRoleRequestForm,
)
from .models import Role, PendingRoleRequest
from .decorators import role_required
from .serializers import CustomTokenObtainPairSerializer
from .email_utils import (
    send_verification_email, send_login_otp,
    notify_superadmins, send_role_approved, send_role_rejected,
)
from audit.models import AuditLog
from audit.services import audit_log

User = get_user_model()
PASSWORD_AUTH_BACKEND = 'django.contrib.auth.backends.ModelBackend'
PENDING_AUTH_BACKEND_SESSION_KEY = 'pending_auth_backend'
logger = logging.getLogger(__name__)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _dashboard_url(user):
    if user.role in (Role.SUPER_ADMIN, Role.ADMIN):
        return '/dashboard/admin/'
    if user.role == Role.UPLOADER:
        return '/dashboard/uploader/'
    return '/dashboard/viewer/'


def _get_client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def _get_jwt_tokens(user):
    refresh = RefreshToken.for_user(user)
    refresh['role'] = user.role
    refresh['email'] = user.email
    refresh['full_name'] = user.full_name
    return {'access': str(refresh.access_token), 'refresh': str(refresh)}


# ── Auth page ──────────────────────────────────────────────────────────────────

def auth_page(request):
    if request.user.is_authenticated:
        return redirect(_dashboard_url(request.user))
    # If redirected here from a protected page, show login tab
    show_login = bool(request.GET.get('next') or request.GET.get('show_login'))
    return render(request, 'accounts/auth.html', {
        'login_form':    LoginForm(request=request),
        'register_form': RegisterForm(),
        'show_login':    show_login,
    })


# ── Register ───────────────────────────────────────────────────────────────────

def register_view(request):
    if request.user.is_authenticated:
        return redirect(_dashboard_url(request.user))

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            audit_log(
                action=AuditLog.Action.REGISTER,
                user=user,
                request=request,
                description=f'New account registered: {user.email}',
                category='auth',
                obj=user,
                fields=['email', 'role', 'is_email_verified', 'is_active'],
            )
            # ── Zero Trust: send email verification before any access ──────────
            try:
                verify_url = send_verification_email(user, request)
                messages.success(
                    request,
                    f'Account created! We sent a verification link to {user.email}. '
                    f'Please check your inbox (and spam folder) to activate your account.'
                )
                if getattr(settings, 'DEBUG', False):
                    messages.info(
                        request, f'[DEBUG] Verification link: {verify_url}')
            except Exception:
                logger.exception('Registration verification email failed')
                # Email failed — delete user so they can retry cleanly
                email = user.email
                user.delete()
                audit_log(
                    action=AuditLog.Action.SUSPICIOUS_ACTIVITY,
                    user=None,
                    request=request,
                    description=f'Registration rolled back — verification email failed for {email}',
                    category='auth',
                )
                messages.error(
                    request,
                    'We could not send a verification email. '
                    'Please check your email address and try again.'
                )
                return render(request, 'accounts/auth.html', {
                    'login_form':    LoginForm(request=request),
                    'register_form': form,
                    'show_register': True,
                })
            return redirect('accounts:check_email')
        return render(request, 'accounts/auth.html', {
            'login_form':    LoginForm(request=request),
            'register_form': form,
            'show_register': True,
        })
    return redirect('accounts:auth')


def check_email_view(request):
    """Shown after signup — tells user to check inbox."""
    return render(request, 'accounts/check_email.html')


def verify_email_view(request, token):
    """
    User clicks the link from their email.
    Zero Trust: token must exist, match, be unexpired, and user must be inactive.
    """
    try:
        user = User.objects.get(email_verify_token=token,
                                is_email_verified=False)
    except User.DoesNotExist:
        return render(request, 'accounts/verify_result.html', {
            'success': False,
            'message': 'This verification link is invalid or has already been used.',
        })

    if not user.email_verify_token_valid:
        return render(request, 'accounts/verify_result.html', {
            'success': False,
            'message': 'This verification link has expired. Please register again or request a new link.',
        })

    # Activate account
    user.is_email_verified = True
    user.is_active = True
    user.email_verify_token = ''
    user.save(update_fields=['is_email_verified',
              'is_active', 'email_verify_token'])

    audit_log(
        action=AuditLog.Action.EMAIL_VERIFIED,
        user=user,
        request=request,
        description=f'Email verified for {user.email}',
        category='auth',
        obj=user,
        fields=['email', 'is_email_verified', 'is_active'],
    )

    return render(request, 'accounts/verify_result.html', {
        'success': True,
        'message': 'Your email has been verified! You can now log in.',
    })


def resend_verification_view(request):
    """Allow user to request a new verification email."""
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        try:
            user = User.objects.get(email=email, is_email_verified=False)
            # Rate limit: only once per 5 minutes
            if user.email_verify_sent_at:
                from datetime import timedelta
                if timezone.now() < user.email_verify_sent_at + timedelta(minutes=5):
                    messages.warning(
                        request, 'Please wait 5 minutes before requesting another email.')
                    return redirect('accounts:check_email')
            verify_url = send_verification_email(user, request)
            messages.success(request, f'Verification email resent to {email}.')
            if getattr(settings, 'DEBUG', False):
                messages.info(
                    request, f'[DEBUG] Verification link: {verify_url}')
        except User.DoesNotExist:
            # Don't reveal whether email exists
            messages.success(
                request, f'If that email exists and is unverified, we sent a new link.')
        return redirect('accounts:check_email')
    return render(request, 'accounts/resend_verification.html')


# ── Login ──────────────────────────────────────────────────────────────────────

def login_view(request):
    if request.user.is_authenticated:
        return redirect(_dashboard_url(request.user))

    if request.method == 'POST':
        form = LoginForm(request=request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            request.session[PENDING_AUTH_BACKEND_SESSION_KEY] = getattr(
                user, 'backend', PASSWORD_AUTH_BACKEND)

            # ── Zero Trust: always require a second factor ─────────────────────
            if user.is_mfa_enabled:
                # TOTP path — redirect to authenticator app OTP entry
                request.session['mfa_user_id'] = user.pk
                audit_log(
                    action=AuditLog.Action.LOGIN_SUCCESS,
                    user=user,
                    request=request,
                    description=f'Login step 1 passed (MFA required) for {user.email}',
                    category='auth',
                    obj=user,
                    fields=['email', 'role', 'is_mfa_enabled'],
                )
                return redirect('accounts:mfa_verify')
            else:
                # Email OTP path — send code and require it before granting session
                try:
                    send_login_otp(user)
                    request.session['otp_user_id'] = user.pk
                    audit_log(
                        action=AuditLog.Action.LOGIN_OTP_SENT,
                        user=user,
                        request=request,
                        description=f'Login OTP sent to {user.email}',
                        category='auth',
                        obj=user,
                        fields=['email', 'role'],
                    )
                    return redirect('accounts:email_otp_verify')
                except ImproperlyConfigured:
                    messages.error(
                        request, 'Email delivery is not configured. Please contact an administrator.')
                except Exception:
                    messages.error(
                        request, 'Could not send verification code. Please try again.')

        audit_log(
            action=AuditLog.Action.LOGIN_FAILED,
            request=request,
            description='Login failed — invalid credentials',
            category='auth',
        )
        return render(request, 'accounts/auth.html', {
            'login_form':    form,
            'register_form': RegisterForm(),
            'show_login':    True,
        })
    return redirect('accounts:auth')


def logout_view(request):
    user = request.user
    audit_log(
        action=AuditLog.Action.LOGOUT,
        user=user,
        request=request,
        description=f'User logged out: {user.email if user.is_authenticated else "anonymous"}',
        category='auth',
    )
    logout(request)
    messages.info(request, 'You have been signed out.')
    return redirect('accounts:auth')


# ── Email OTP verify (all non-TOTP users) ─────────────────────────────────────

def email_otp_verify_view(request):
    """
    Zero Trust step 2: verify the 6-digit code sent to email.
    Only issues a session after this succeeds.
    """
    user_id = request.session.get('otp_user_id')
    if not user_id:
        return redirect('accounts:auth')

    user = get_object_or_404(User, pk=user_id)

    if request.method == 'POST':
        form = EmailOTPForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data['otp'].strip()

            if not user.login_otp_valid:
                form.add_error(
                    'otp', 'Code has expired. Please log in again to receive a new code.')
            elif user.login_otp_attempts >= 5:
                form.add_error(
                    'otp', 'Too many attempts. Please log in again.')
                request.session.pop('otp_user_id', None)
            elif user.verify_login_otp(code):
                # ── Grant session only now ─────────────────────────────────────
                user.last_login_ip = _get_client_ip(request)
                user.last_user_agent = request.META.get(
                    'HTTP_USER_AGENT', '')[:300]
                user.save(update_fields=['last_login_ip', 'last_user_agent'])
                login(
                    request,
                    user,
                    backend=request.session.get(
                        PENDING_AUTH_BACKEND_SESSION_KEY,
                        PASSWORD_AUTH_BACKEND,
                    ),
                )
                request.session.pop('otp_user_id', None)
                request.session.pop(PENDING_AUTH_BACKEND_SESSION_KEY, None)
                audit_log(
                    action=AuditLog.Action.LOGIN_OTP_VERIFIED,
                    user=user,
                    request=request,
                    description=f'Login OTP verified — session granted for {user.email}',
                    category='auth',
                    obj=user,
                    fields=['email', 'role', 'last_login_ip'],
                )
                messages.success(request, f'Welcome back, {user.full_name}!')
                return redirect(_dashboard_url(user))
            else:
                remaining = max(0, 5 - user.login_otp_attempts)
                audit_log(
                    action=AuditLog.Action.LOGIN_OTP_FAILED,
                    user=user,
                    request=request,
                    description=f'Invalid login OTP for {user.email} — {remaining} attempt(s) remaining',
                    category='auth',
                    obj=user,
                    fields=['email'],
                )
                form.add_error(
                    'otp', f'Invalid code. {remaining} attempt(s) remaining.')
    else:
        form = EmailOTPForm()

    # Mask email for display (zero@ex***le.com)
    parts = user.email.split('@')
    masked = parts[0][:2] + '***' + '@' + \
        parts[1] if len(parts) == 2 else user.email

    return render(request, 'accounts/email_otp_verify.html', {
        'form':         form,
        'masked_email': masked,
    })


def resend_login_otp_view(request):
    """Resend the login OTP — rate limited."""
    user_id = request.session.get('otp_user_id')
    if not user_id:
        return redirect('accounts:auth')
    user = get_object_or_404(User, pk=user_id)
    from datetime import timedelta
    if user.login_otp_created_at and timezone.now() < user.login_otp_created_at + timedelta(minutes=1):
        messages.warning(
            request, 'Please wait before requesting another code.')
    else:
        try:
            send_login_otp(user)
            messages.success(
                request, 'A new code has been sent to your email.')
        except ImproperlyConfigured:
            messages.error(
                request, 'Email delivery is not configured. Please contact an administrator.')
        except Exception:
            messages.error(request, 'Could not send code. Please try again.')
    return redirect('accounts:email_otp_verify')


# ── TOTP MFA ───────────────────────────────────────────────────────────────────

def mfa_verify_view(request):
    user_id = request.session.get('mfa_user_id')
    if not user_id:
        return redirect('accounts:auth')
    user = get_object_or_404(User, pk=user_id)

    if request.method == 'POST':
        form = MFAVerifyForm(request.POST)
        if form.is_valid():
            device = match_token(user, form.cleaned_data['token'].strip())
            if device:
                user.last_login_ip = _get_client_ip(request)
                user.last_user_agent = request.META.get(
                    'HTTP_USER_AGENT', '')[:300]
                user.save(update_fields=['last_login_ip', 'last_user_agent'])
                login(
                    request,
                    user,
                    backend=request.session.get(
                        PENDING_AUTH_BACKEND_SESSION_KEY,
                        PASSWORD_AUTH_BACKEND,
                    ),
                )
                request.session.pop('mfa_user_id', None)
                request.session.pop(PENDING_AUTH_BACKEND_SESSION_KEY, None)
                audit_log(
                    action=AuditLog.Action.MFA_VERIFIED,
                    user=user,
                    request=request,
                    description=f'MFA verified — session granted for {user.email}',
                    category='auth',
                    obj=user,
                    fields=['email', 'role', 'last_login_ip'],
                )
                messages.success(request, f'Welcome back, {user.full_name}!')
                return redirect(_dashboard_url(user))
            audit_log(
                action=AuditLog.Action.LOGIN_FAILED,
                user=user,
                request=request,
                description=f'MFA verification failed for {user.email}',
                category='auth',
                obj=user,
                fields=['email'],
            )
            form.add_error('token', 'Invalid or expired code.')
    else:
        form = MFAVerifyForm()
    return render(request, 'accounts/mfa_verify.html', {'form': form})


@login_required
def mfa_setup_view(request):
    user = request.user
    TOTPDevice.objects.filter(user=user, confirmed=False).delete()
    if TOTPDevice.objects.filter(user=user, confirmed=True).exists() and user.is_mfa_enabled:
        messages.info(request, 'TOTP MFA is already enabled.')
        return redirect('accounts:profile')

    device = TOTPDevice.objects.create(
        user=user, name='authenticator', confirmed=False)
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(device.config_url)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    qr_svg = buf.getvalue().decode('utf-8')

    if request.method == 'POST':
        form = MFASetupForm(request.POST)
        if form.is_valid():
            if device.verify_token(form.cleaned_data['confirm_token'].strip()):
                device.confirmed = True
                device.save(update_fields=['confirmed'])
                user.is_mfa_enabled = True
                user.save(update_fields=['is_mfa_enabled'])
                audit_log(
                    action=AuditLog.Action.MFA_SETUP,
                    user=user,
                    request=request,
                    description=f'TOTP MFA enabled for {user.email}',
                    category='auth',
                    obj=user,
                    fields=['email', 'is_mfa_enabled'],
                )
                messages.success(request, '✓ Authenticator app MFA enabled.')
                return redirect(_dashboard_url(user))
            form.add_error(
                'confirm_token', 'Code did not match. Make sure your device clock is synced.')
    else:
        form = MFASetupForm()

    return render(request, 'accounts/mfa_setup.html', {'form': form, 'device': device, 'qr_svg': qr_svg})


@login_required
def mfa_disable_view(request):
    if request.method == 'POST':
        TOTPDevice.objects.filter(user=request.user).delete()
        request.user.is_mfa_enabled = False
        request.user.save(update_fields=['is_mfa_enabled'])
        audit_log(
            action=AuditLog.Action.MFA_DISABLED,
            user=request.user,
            request=request,
            description=f'TOTP MFA disabled for {request.user.email}',
            category='auth',
            obj=request.user,
            fields=['email', 'is_mfa_enabled'],
        )
        messages.success(
            request, 'Authenticator app MFA disabled. You will now receive email OTP codes.')
    return redirect('accounts:profile')


# ── Profile ────────────────────────────────────────────────────────────────────

@login_required
def profile_view(request):
    tokens = _get_jwt_tokens(request.user) if request.GET.get(
        'show_token') else None
    return render(request, 'accounts/profile.html', {'tokens': tokens})


def pending_approval_view(request):
    return render(request, 'accounts/pending_approval.html')


# ── Role requests ──────────────────────────────────────────────────────────────

@login_required
def request_role_view(request):
    if hasattr(request.user, 'role_request'):
        messages.info(request, 'You already have a pending role request.')
        return redirect('accounts:profile')
    if request.method == 'POST':
        form = RoleRequestForm(request.POST)
        if form.is_valid():
            rr = form.save(commit=False)
            rr.user = request.user
            rr.save()
            audit_log(
                action=AuditLog.Action.ROLE_REQUESTED,
                user=request.user,
                request=request,
                description=f'{request.user.email} requested role: {rr.requested_role}',
                category='role',
                obj=rr,
                fields=['user', 'requested_role', 'reason', 'status'],
            )
            notify_superadmins(
                subject=f'Role request: {request.user.email}',
                message=(
                    f'{request.user.full_name} ({request.user.email}) '
                    f'requested the {rr.requested_role} role.\n\nReason: {rr.reason}'
                ),
            )
            messages.success(
                request, 'Role request submitted. A Super Admin will review it.')
            return redirect('accounts:profile')
    else:
        form = RoleRequestForm()
    return render(request, 'accounts/request_role.html', {'form': form})


@login_required
@role_required('super_admin')
def role_requests_view(request):
    qs = PendingRoleRequest.objects.select_related(
        'user').filter(status='pending')
    return render(request, 'accounts/role_requests.html', {'requests': qs})


@login_required
@role_required('super_admin')
def review_role_request_view(request, pk):
    rr = get_object_or_404(PendingRoleRequest, pk=pk)
    if request.method == 'POST':
        form = ReviewRoleRequestForm(request.POST)
        if form.is_valid():
            action = form.cleaned_data['action']
            note = form.cleaned_data.get('review_note', '')
            rr.status = action
            rr.reviewed_by = request.user
            rr.reviewed_at = timezone.now()
            rr.review_note = note
            rr.save()
            if action == 'approved':
                rr.user.role = rr.requested_role
                rr.user.is_approved = True
                rr.user.approved_by = request.user
                rr.user.approved_at = timezone.now()
                rr.user.is_staff = True
                rr.user.save(update_fields=[
                             'role', 'is_approved', 'approved_by', 'approved_at', 'is_staff'])
                audit_log(
                    action=AuditLog.Action.ROLE_APPROVED,
                    user=request.user,
                    request=request,
                    description=f'{request.user.email} approved {rr.user.email} for role: {rr.requested_role}',
                    category='role',
                    obj=rr,
                    fields=['user', 'requested_role', 'status',
                            'reviewed_by', 'review_note'],
                )
                send_role_approved(rr.user, rr.requested_role)
            else:
                audit_log(
                    action=AuditLog.Action.ROLE_REJECTED,
                    user=request.user,
                    request=request,
                    description=f'{request.user.email} rejected {rr.user.email} for role: {rr.requested_role}',
                    category='role',
                    obj=rr,
                    fields=['user', 'requested_role', 'status',
                            'reviewed_by', 'review_note'],
                )
                send_role_rejected(rr.user, rr.requested_role, note)
            messages.success(request, f'Request {action} for {rr.user.email}.')
            return redirect('accounts:role_requests')
    else:
        form = ReviewRoleRequestForm()
    return render(request, 'accounts/review_request.html', {'rr': rr, 'form': form})


# ── JWT API ────────────────────────────────────────────────────────────────────

class JWTLoginView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            audit_log(
                action=AuditLog.Action.LOGIN_FAILED,
                request=request,
                description='JWT login failed — invalid credentials',
                category='auth',
            )
            return Response({'error': 'Invalid credentials'}, status=drf_status.HTTP_401_UNAUTHORIZED)
        user = serializer.user
        if not user.is_email_verified:
            audit_log(
                action=AuditLog.Action.LOGIN_FAILED,
                user=user,
                request=request,
                description=f'JWT login blocked — email not verified for {user.email}',
                category='auth',
                obj=user,
                fields=['email'],
            )
            return Response({'error': 'Email not verified'}, status=drf_status.HTTP_403_FORBIDDEN)
        if not user.can_access():
            audit_log(
                action=AuditLog.Action.LOGIN_FAILED,
                user=user,
                request=request,
                description=f'JWT login blocked — account pending approval for {user.email}',
                category='auth',
                obj=user,
                fields=['email'],
            )
            return Response({'error': 'Account pending approval'}, status=drf_status.HTTP_403_FORBIDDEN)
        if user.is_mfa_enabled:
            audit_log(
                action=AuditLog.Action.LOGIN_SUCCESS,
                user=user,
                request=request,
                description=f'JWT login step 1 passed (MFA required) for {user.email}',
                category='auth',
                obj=user,
                fields=['email', 'role'],
            )
            return Response({'mfa_required': True, 'user_id': user.pk})
        audit_log(
            action=AuditLog.Action.LOGIN_SUCCESS,
            user=user,
            request=request,
            description=f'JWT login successful for {user.email}',
            category='auth',
            obj=user,
            fields=['email', 'role'],
        )
        return Response(serializer.validated_data)


@api_view(['POST'])
@permission_classes([AllowAny])
def api_mfa_verify(request):
    user_id = request.data.get('user_id')
    token = request.data.get('token', '').strip()
    if not user_id or not token:
        return Response({'error': 'user_id and token required'}, status=400)
    user = get_object_or_404(User, pk=user_id)
    device = match_token(user, token)
    if not device:
        audit_log(
            action=AuditLog.Action.LOGIN_OTP_FAILED,
            user=user,
            request=request,
            description=f'API MFA verification failed for {user.email}',
            category='auth',
            obj=user,
            fields=['email'],
        )
        return Response({'error': 'Invalid OTP'}, status=drf_status.HTTP_401_UNAUTHORIZED)
    audit_log(
        action=AuditLog.Action.MFA_VERIFIED,
        user=user,
        request=request,
        description=f'API MFA verified — JWT issued for {user.email}',
        category='auth',
        obj=user,
        fields=['email', 'role'],
    )
    tokens = _get_jwt_tokens(user)
    return Response({**tokens, 'user': {'id': user.pk, 'email': user.email, 'role': user.role}})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_logout(request):
    try:
        RefreshToken(request.data.get('refresh')).blacklist()
        audit_log(
            action=AuditLog.Action.LOGOUT,
            user=request.user,
            request=request,
            description=f'API logout for {request.user.email}',
            category='auth',
        )
        return Response({'detail': 'Logged out.'})
    except Exception as e:
        return Response({'error': str(e)}, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_me(request):
    u = request.user
    return Response({'id': u.pk, 'email': u.email, 'full_name': u.full_name,
                     'role': u.role, 'mfa_enabled': u.is_mfa_enabled})
