from django.urls import path, reverse_lazy
from django.contrib.auth import views as auth_views
from . import views

app_name = 'accounts'

urlpatterns = [
    # Auth slider page
    path('',                      views.auth_page,                 name='auth'),
    path('login/',                views.login_view,                name='login'),
    path('register/',             views.register_view,             name='register'),
    path('logout/',               views.logout_view,               name='logout'),

    # Email verification
    path('check-email/',          views.check_email_view,
         name='check_email'),
    path('verify/<str:token>/',   views.verify_email_view,
         name='verify_email'),
    path('resend-verification/',  views.resend_verification_view,
         name='resend_verification'),

    # Email OTP (step-2 for non-TOTP users)
    path('otp/verify/',           views.email_otp_verify_view,
         name='email_otp_verify'),
    path('otp/resend/',           views.resend_login_otp_view,
         name='resend_login_otp'),

    # TOTP MFA
    path('mfa/verify/',           views.mfa_verify_view,           name='mfa_verify'),
    path('mfa/setup/',            views.mfa_setup_view,            name='mfa_setup'),
    path('mfa/disable/',          views.mfa_disable_view,
         name='mfa_disable'),

    # Profile & role management
    path('profile/',              views.profile_view,              name='profile'),
    path('pending/',              views.pending_approval_view,
         name='pending_approval'),
    path('request-role/',         views.request_role_view,
         name='request_role'),
    path('admin/role-requests/',
         views.role_requests_view,        name='role_requests'),
    path('admin/role-requests/<int:pk>/review/',
         views.review_role_request_view,  name='review_role_request'),

    # Password reset (Django builtins)
    path('password-reset/', auth_views.PasswordResetView.as_view(
        template_name='registration/password_reset_form.html',
        success_url=reverse_lazy('accounts:password_reset_done')
    ), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='registration/password_reset_done.html'
    ), name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='registration/password_reset_confirm.html',
        success_url=reverse_lazy('accounts:password_reset_complete')
    ), name='password_reset_confirm'),
    path('password-reset-complete/', auth_views.PasswordResetCompleteView.as_view(
        template_name='registration/password_reset_complete.html'
    ), name='password_reset_complete'),
]
