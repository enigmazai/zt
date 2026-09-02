from django.urls import path
from . import views

app_name = 'media'

urlpatterns = [
    path('',                         views.viewer_dashboard,   name='home'),
    path('dashboard/',               views.dashboard,          name='dashboard'),
    path('dashboard/admin/',         views.admin_dashboard,    name='admin_dashboard'),
    path('dashboard/audit-logs/',    views.audit_log_list,     name='audit_log_list'),
    path('dashboard/uploader/',      views.uploader_dashboard, name='uploader_dashboard'),
    path('dashboard/viewer/',        views.viewer_dashboard,   name='viewer_dashboard'),
    path('upload/',                  views.upload_media,       name='upload'),
    path('assets/<int:pk>/',         views.media_detail,       name='media_detail'),
    path('assets/<int:pk>/edit/',    views.edit_media,         name='edit_media'),
    path('assets/<int:pk>/delete/',  views.delete_media,       name='delete_media'),
    path('assets/<int:pk>/publish/', views.publish_media,      name='publish_media'),
]
