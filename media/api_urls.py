from django.urls import path
from accounts.views import JWTLoginView, api_mfa_verify, api_logout, api_me
from .api_views import (
    MediaListAPIView, MediaDetailAPIView,
    MediaUploadAPIView, MediaDeleteAPIView,
)

app_name = 'media_api'

urlpatterns = [
    # Auth
    path('auth/login/',      JWTLoginView.as_view(),  name='jwt_login'),
    path('auth/mfa-verify/', api_mfa_verify,          name='mfa_verify'),
    path('auth/logout/',     api_logout,               name='logout'),
    path('auth/me/',         api_me,                   name='me'),
    # Media
    path('media/',           MediaListAPIView.as_view(),   name='media_list'),
    path('media/upload/',    MediaUploadAPIView.as_view(),  name='media_upload'),
    path('media/<int:pk>/',  MediaDetailAPIView.as_view(),  name='media_detail'),
    path('media/<int:pk>/delete/', MediaDeleteAPIView.as_view(), name='media_delete'),
]
