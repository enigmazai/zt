import os
import cloudinary.uploader
from django.conf import settings
from django.db.models import QuerySet
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from .models import MediaAsset
from .serializers import MediaAssetSerializer
from accounts.models import Role
from audit.models import AuditLog
from audit.services import audit_log


class RolePermission:
    def _is_admin(self, user):
        return user.role in (Role.ADMIN, Role.SUPER_ADMIN)

    def _is_uploader(self, user):
        return user.role in (Role.UPLOADER, Role.ADMIN, Role.SUPER_ADMIN)


class MediaListAPIView(RolePermission, generics.ListAPIView):
    serializer_class = MediaAssetSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self) -> QuerySet[MediaAsset]:
        user = self.request.user
        qs: QuerySet[MediaAsset] = MediaAsset.objects.select_related(
            'uploaded_by', 'category')
        if self._is_admin(user):
            return qs.all()
        return qs.filter(status='published').exclude(visibility='private')


class MediaDetailAPIView(RolePermission, generics.RetrieveAPIView):
    serializer_class = MediaAssetSerializer
    permission_classes = [IsAuthenticated]
    queryset = MediaAsset.objects.all()

    def retrieve(self, request, *args, **kwargs):
        asset = self.get_object()
        if not asset.can_view(request.user):
            audit_log(
                action=AuditLog.Action.PERMISSION_DENIED,
                user=request.user,
                request=request,
                description=f'API access denied to media "{asset.title}" (id={asset.pk})',
                category='media',
                obj=asset,
                fields=['title', 'visibility', 'status'],
            )
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        audit_log(
            action=AuditLog.Action.MEDIA_VIEWED,
            user=request.user,
            request=request,
            description=f'API media viewed: "{asset.title}" (id={asset.pk})',
            category='media',
            obj=asset,
            fields=['title', 'file_type'],
        )
        return super().retrieve(request, *args, **kwargs)


class MediaUploadAPIView(RolePermission, APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        if not self._is_uploader(request.user):
            audit_log(
                action=AuditLog.Action.PERMISSION_DENIED,
                user=request.user,
                request=request,
                description=f'API upload denied — not an uploader ({request.user.email})',
                category='media',
            )
            return Response({'error': 'Uploaders only'}, status=status.HTTP_403_FORBIDDEN)

        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file provided'}, status=400)

        # Extension check
        ext = os.path.splitext(file.name)[1].lower()
        if ext not in settings.ALLOWED_UPLOAD_EXTENSIONS:
            audit_log(
                action=AuditLog.Action.SUSPICIOUS_ACTIVITY,
                user=request.user,
                request=request,
                description=f'API upload rejected — disallowed file type {ext} by {request.user.email}',
                category='media',
            )
            return Response({'error': f'File type {ext} not allowed'}, status=400)

        # Size check
        if file.size > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
            audit_log(
                action=AuditLog.Action.SUSPICIOUS_ACTIVITY,
                user=request.user,
                request=request,
                description=f'API upload rejected — file too large ({file.size} bytes) by {request.user.email}',
                category='media',
            )
            return Response({'error': f'Max file size is {settings.MAX_UPLOAD_SIZE_MB} MB'}, status=400)

        result = cloudinary.uploader.upload(
            file, folder='media_platform', resource_type='auto',
            use_filename=True, unique_filename=True,
        )

        public_id = result['public_id']
        file_format = result.get('format')
        if file_format and not public_id.lower().endswith(f'.{file_format.lower()}'):
            public_id = f'{public_id}.{file_format}'
        resource_type = result.get('resource_type')
        file_type = resource_type if resource_type in {
            'image', 'video'} else 'raw'

        asset = MediaAsset.objects.create(
            title=request.data.get('title', file.name),
            description=request.data.get('description', ''),
            file=public_id,
            file_public_id=result['public_id'],
            file_format=file_format or '',
            file_version=result.get('version'),
            file_type=file_type,
            file_size=result.get('bytes', file.size),
            uploaded_by=request.user,
            status='draft',
        )
        audit_log(
            action=AuditLog.Action.MEDIA_UPLOADED,
            user=request.user,
            request=request,
            description=f'API media uploaded: "{asset.title}" ({asset.file_type}, {asset.file_size} bytes)',
            category='media',
            obj=asset,
            fields=['title', 'file_type', 'file_size', 'status', 'visibility'],
        )
        return Response(MediaAssetSerializer(asset).data, status=status.HTTP_201_CREATED)


class MediaDeleteAPIView(RolePermission, APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        from django.shortcuts import get_object_or_404
        asset = get_object_or_404(MediaAsset, pk=pk)
        if not asset.can_delete(request.user):
            audit_log(
                action=AuditLog.Action.PERMISSION_DENIED,
                user=request.user,
                request=request,
                description=f'API delete denied for media "{asset.title}" (id={asset.pk})',
                category='media',
                obj=asset,
                fields=['title'],
            )
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        if asset.file:
            cloudinary.uploader.destroy(str(asset.file), resource_type='auto')
        audit_log(
            action=AuditLog.Action.MEDIA_DELETED,
            user=request.user,
            request=request,
            description=f'API media deleted: "{asset.title}" (id={asset.pk})',
            category='media',
            obj=asset,
            fields=['title', 'file_type', 'file_size', 'status'],
        )
        asset.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
