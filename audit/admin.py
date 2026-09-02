from django.contrib import admin

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        'created_at', 'user_email', 'action', 'category',
        'ip_address', 'path', 'method',
    )
    list_filter = ('action', 'category', 'method', 'created_at')
    search_fields = ('user_email', 'description', 'ip_address', 'path')
    readonly_fields = (
        'user', 'user_email', 'action', 'category', 'description',
        'content_type', 'object_id', 'before', 'after',
        'ip_address', 'user_agent', 'path', 'method', 'created_at',
    )
    date_hierarchy = 'created_at'
    list_per_page = 50

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser