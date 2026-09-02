from pathlib import Path

from django.conf import settings
from django.template import Template
from django.test import TestCase
from django.urls import reverse

from accounts.models import Role, User
from audit.models import AuditLog


class MediaTemplateRegressionTests(TestCase):
    def test_auth_template_compiles(self):
        template_path = Path(settings.BASE_DIR) / \
            'templates' / 'accounts' / 'auth.html'
        Template(template_path.read_text(encoding='utf-8'))

    def test_cloudinary_settings_are_configured(self):
        self.assertTrue(settings.CLOUDINARY_CONFIGURED)


class AuditLogPageTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='test-password',
            role=Role.ADMIN,
            is_active=True,
            is_approved=True,
            is_email_verified=True,
        )
        self.viewer = User.objects.create_user(
            email='viewer@example.com',
            password='test-password',
            role=Role.VIEWER,
            is_active=True,
            is_email_verified=True,
        )

    def test_admin_can_filter_audit_logs(self):
        AuditLog.objects.create(
            user=self.admin,
            user_email=self.admin.email,
            action=AuditLog.Action.LOGIN_SUCCESS,
            category='auth',
            description='Successful sign in.',
        )
        self.client.force_login(self.admin)

        response = self.client.get(
            reverse('media:audit_log_list'),
            {'action': AuditLog.Action.LOGIN_SUCCESS},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Successful sign in.')
        self.assertContains(response, 'Login Successful')

    def test_viewer_cannot_access_audit_logs(self):
        self.client.force_login(self.viewer)

        response = self.client.get(reverse('media:audit_log_list'))

        self.assertEqual(response.status_code, 403)
