from django.contrib import admin
from django.shortcuts import render

from audit.models import AuditLog


@admin.site.admin_view
def audit_dashboard(request):
    """Simple admin-accessible dashboard showing recent audit logs."""
    logs = AuditLog.objects.all()[:20]
    return render(request, 'admin/audit_dashboard.html', {'logs': logs})
