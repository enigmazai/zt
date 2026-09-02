import os
import cloudinary.uploader

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import Http404, JsonResponse
from django.utils import timezone
from django.db.models import Q, Sum
from django.conf import settings

from .models import MediaAsset, MediaCategory
from .forms import MediaUploadForm, MediaEditForm
from accounts.decorators import role_required
from accounts.models import Role
from audit.models import AuditLog
from audit.services import audit_log

# File type → icon/label map used in templates
FILE_TYPE_META = {
    'video':    {'icon': '🎬', 'label': 'Video',    'color': 'teal'},
    'image':    {'icon': '🖼️',  'label': 'Image',    'color': 'blue'},
    'audio':    {'icon': '🎵', 'label': 'Audio',    'color': 'purple'},
    'raw':      {'icon': '📄', 'label': 'Document', 'color': 'amber'},
    'document': {'icon': '📄', 'label': 'Document', 'color': 'amber'},
}


def _file_type_from_ext(filename):
    ext = os.path.splitext(filename)[1].lower()
    video_exts = {'.mp4', '.mov', '.avi',
                  '.mkv', '.webm', '.flv', '.wmv', '.m4v'}
    audio_exts = {'.mp3', '.wav', '.aac', '.flac', '.ogg', '.m4a', '.wma'}
    image_exts = {'.jpg', '.jpeg', '.png',
                  '.gif', '.webp', '.svg', '.bmp', '.tiff'}
    if ext in video_exts:
        return 'video'
    if ext in audio_exts:
        return 'audio'
    if ext in image_exts:
        return 'image'
    return 'raw'


# ── Dashboard routing ──────────────────────────────────────────────────────────

@login_required
def dashboard(request):
    role = request.user.role
    if role in (Role.SUPER_ADMIN, Role.ADMIN):
        return redirect('media:admin_dashboard')
    if role == Role.UPLOADER:
        return redirect('media:uploader_dashboard')
    return redirect('media:viewer_dashboard')


# ── Admin dashboard ────────────────────────────────────────────────────────────

@login_required
@role_required('admin', 'super_admin')
def admin_dashboard(request):
    from accounts.models import User, PendingRoleRequest
    assets = MediaAsset.objects.select_related('uploaded_by')
    context = {
        'total_users':    User.objects.count(),
        'total_assets':   assets.count(),
        'pending_roles':  PendingRoleRequest.objects.filter(status='pending').count(),
        'published_count': assets.filter(status='published').count(),
        'draft_count':    assets.filter(status='draft').count(),
        'recent_assets':  assets.order_by('-created_at')[:10],
        'recent_users':   User.objects.order_by('-date_joined')[:5],
        'pending_assets': assets.filter(status='draft').order_by('-created_at')[:5],
    }
    return render(request, 'media/admin_dashboard.html', context)


@login_required
@role_required('admin', 'super_admin')
def audit_log_list(request):
    """Show administrators the immutable security and activity audit trail."""
    logs = AuditLog.objects.select_related('user').all()
    q = request.GET.get('q', '').strip()
    action = request.GET.get('action', '')
    category = request.GET.get('category', '')
    action_values = {value for value, _label in AuditLog.Action.choices}

    if q:
        logs = logs.filter(
            Q(user_email__icontains=q) |
            Q(description__icontains=q) |
            Q(ip_address__icontains=q) |
            Q(path__icontains=q)
        )
    if action in action_values:
        logs = logs.filter(action=action)
    if category:
        logs = logs.filter(category=category)

    page_obj = Paginator(logs, 25).get_page(request.GET.get('page'))
    categories = (
        AuditLog.objects.exclude(category='')
        .values_list('category', flat=True)
        .distinct()
        .order_by('category')
    )
    return render(request, 'media/audit_log_list.html', {
        'page_obj': page_obj,
        'q': q,
        'action': action,
        'category': category,
        'action_choices': AuditLog.Action.choices,
        'categories': categories,
    })


# ── Uploader dashboard ─────────────────────────────────────────────────────────

@login_required
@role_required('uploader', 'admin', 'super_admin')
def uploader_dashboard(request):
    my_uploads = MediaAsset.objects.filter(
        uploaded_by=request.user).order_by('-created_at')

    # Stats
    stats = {
        'total':       my_uploads.count(),
        'published':   my_uploads.filter(status='published').count(),
        'drafts':      my_uploads.filter(status='draft').count(),
        'total_views': my_uploads.aggregate(v=Sum('view_count'))['v'] or 0,
        'total_size':  my_uploads.aggregate(s=Sum('file_size'))['s'] or 0,
        'videos':      my_uploads.filter(file_type='video').count(),
        'images':      my_uploads.filter(file_type='image').count(),
        'audio':       my_uploads.filter(file_type='audio').count(),
        'docs':        my_uploads.filter(file_type__in=['raw', 'document']).count(),
    }

    # Filter
    status_filter = request.GET.get('status', '')
    type_filter = request.GET.get('type', '')
    q = request.GET.get('q', '')
    filtered = my_uploads
    if status_filter:
        filtered = filtered.filter(status=status_filter)
    if type_filter:
        filtered = filtered.filter(file_type=type_filter)
    if q:
        filtered = filtered.filter(
            Q(title__icontains=q) | Q(tags__icontains=q))

    return render(request, 'media/uploader_dashboard.html', {
        'uploads':        filtered,
        'stats':          stats,
        'status_filter':  status_filter,
        'type_filter':    type_filter,
        'q':              q,
        'file_type_meta': FILE_TYPE_META,
        'allowed_exts':   settings.ALLOWED_UPLOAD_EXTENSIONS,
    })


# ── Viewer dashboard ───────────────────────────────────────────────────────────

@login_required
def viewer_dashboard(request):
    assets = MediaAsset.objects.filter(
        status='published').select_related('uploaded_by', 'category')
    if not request.user.is_admin:
        assets = assets.filter(Q(visibility='public') |
                               Q(visibility='internal'))

    q = request.GET.get('q', '')
    category = request.GET.get('category', '')
    ftype = request.GET.get('type', '')
    if q:
        assets = assets.filter(Q(title__icontains=q) | Q(
            tags__icontains=q) | Q(description__icontains=q))
    if category:
        assets = assets.filter(category_id=category)
    if ftype:
        assets = assets.filter(file_type=ftype)

    return render(request, 'media/viewer_dashboard.html', {
        'assets':     assets.order_by('-published_at'),
        'categories': MediaCategory.objects.all(),
        'q': q, 'category': category, 'ftype': ftype,
        'file_type_meta': FILE_TYPE_META,
    })


# ── Upload ─────────────────────────────────────────────────────────────────────

@login_required
@role_required('uploader', 'admin', 'super_admin')
def upload_media(request):
    allowed_exts = settings.ALLOWED_UPLOAD_EXTENSIONS
    max_mb = settings.MAX_UPLOAD_SIZE_MB

    if request.method == 'POST':
        form = MediaUploadForm(request.POST, request.FILES)
        if form.is_valid():
            f = request.FILES.get('file')
            if not f:
                messages.error(request, 'Please select a file.')
                return render(request, 'media/upload.html', {'form': form, 'allowed_exts': allowed_exts, 'max_mb': max_mb})

            ext = os.path.splitext(f.name)[1].lower()
            if ext not in allowed_exts:
                messages.error(request, f'File type "{ext}" is not supported.')
                return render(request, 'media/upload.html', {'form': form, 'allowed_exts': allowed_exts, 'max_mb': max_mb})

            if f.size > max_mb * 1024 * 1024:
                messages.error(request, f'File exceeds the {max_mb} MB limit.')
                return render(request, 'media/upload.html', {'form': form, 'allowed_exts': allowed_exts, 'max_mb': max_mb})

            try:
                result = cloudinary.uploader.upload(
                    f, folder='media_platform',
                    resource_type='auto',
                    use_filename=True, unique_filename=True,
                )
            except Exception as e:
                messages.error(request, f'Upload failed: {e}')
                return render(request, 'media/upload.html', {'form': form, 'allowed_exts': allowed_exts, 'max_mb': max_mb})

            asset = form.save(commit=False)
            asset.uploaded_by = request.user
            public_id = result['public_id']
            file_format = result.get('format')
            if file_format and not public_id.lower().endswith(f'.{file_format.lower()}'):
                public_id = f'{public_id}.{file_format}'
            asset.file = public_id
            asset.file_public_id = result['public_id']
            asset.file_format = file_format or ''
            asset.file_version = result.get('version')
            asset.file_size = result.get('bytes', f.size)
            resource_type = result.get('resource_type')
            asset.file_type = (
                resource_type if resource_type in {'image', 'video'}
                else _file_type_from_ext(f'.{file_format}' if file_format else f.name)
            )
            if result.get('duration'):
                asset.duration = result['duration']
            asset.save()
            audit_log(
                action=AuditLog.Action.MEDIA_UPLOADED,
                user=request.user,
                request=request,
                description=f'Media uploaded: "{asset.title}" ({asset.file_type}, {asset.file_size} bytes)',
                category='media',
                obj=asset,
                fields=['title', 'file_type',
                        'file_size', 'status', 'visibility'],
            )
            messages.success(
                request, f'✓ "{asset.title}" uploaded successfully!')
            return redirect('media:uploader_dashboard')
    else:
        form = MediaUploadForm()

    return render(request, 'media/upload.html', {
        'form':         form,
        'allowed_exts': allowed_exts,
        'max_mb':       max_mb,
    })


# ── Detail ─────────────────────────────────────────────────────────────────────

@login_required
def media_detail(request, pk):
    asset = get_object_or_404(MediaAsset, pk=pk)
    if not asset.can_view(request.user):
        audit_log(
            action=AuditLog.Action.PERMISSION_DENIED,
            user=request.user,
            request=request,
            description=f'Access denied to media "{asset.title}" (id={asset.pk})',
            category='media',
            obj=asset,
            fields=['title', 'visibility', 'status'],
        )
        raise Http404
    asset.view_count += 1
    asset.save(update_fields=['view_count'])
    audit_log(
        action=AuditLog.Action.MEDIA_VIEWED,
        user=request.user,
        request=request,
        description=f'Media viewed: "{asset.title}" (id={asset.pk})',
        category='media',
        obj=asset,
        fields=['title', 'file_type'],
    )
    meta = FILE_TYPE_META.get(
        asset.file_type, {'icon': '📁', 'label': 'File', 'color': 'neutral'})
    preview_url = asset.delivery_url
    download_url = asset.download_url

    can_delete = asset.can_delete(request.user)
    return render(request, 'media/detail.html', {
        'asset': asset,
        'meta': meta,
        'can_delete': can_delete,
        'preview_url': preview_url,
        'download_url': download_url,
    })


# ── Edit ───────────────────────────────────────────────────────────────────────

@login_required
def edit_media(request, pk):
    asset = get_object_or_404(MediaAsset, pk=pk)
    if not asset.can_edit(request.user):
        audit_log(
            action=AuditLog.Action.PERMISSION_DENIED,
            user=request.user,
            request=request,
            description=f'Edit denied for media "{asset.title}" (id={asset.pk})',
            category='media',
            obj=asset,
            fields=['title'],
        )
        messages.error(request, 'Permission denied.')
        return redirect('media:dashboard')
    if request.method == 'POST':
        form = MediaEditForm(request.POST, instance=asset)
        if form.is_valid():
            form.save()
            audit_log(
                action=AuditLog.Action.MEDIA_UPDATED,
                user=request.user,
                request=request,
                description=f'Media updated: "{asset.title}" (id={asset.pk})',
                category='media',
                obj=asset,
                fields=['title', 'description', 'category',
                        'tags', 'visibility', 'status'],
            )
            messages.success(request, 'Asset updated.')
            return redirect('media:media_detail', pk=asset.pk)
    else:
        form = MediaEditForm(instance=asset)
    return render(request, 'media/edit.html', {'form': form, 'asset': asset})


# ── Delete ─────────────────────────────────────────────────────────────────────

@login_required
def delete_media(request, pk):
    asset = get_object_or_404(MediaAsset, pk=pk)
    if not asset.can_delete(request.user):
        audit_log(
            action=AuditLog.Action.PERMISSION_DENIED,
            user=request.user,
            request=request,
            description=f'Delete denied for media "{asset.title}" (id={asset.pk})',
            category='media',
            obj=asset,
            fields=['title'],
        )
        messages.error(request, 'Permission denied.')
        return redirect('media:dashboard')
    if request.method == 'POST':
        if asset.file:
            try:
                cloudinary.uploader.destroy(
                    str(asset.file), resource_type='auto')
            except Exception:
                pass
        audit_log(
            action=AuditLog.Action.MEDIA_DELETED,
            user=request.user,
            request=request,
            description=f'Media deleted: "{asset.title}" (id={asset.pk})',
            category='media',
            obj=asset,
            fields=['title', 'file_type', 'file_size', 'status'],
        )
        asset.delete()
        messages.success(request, 'Asset deleted.')
        return redirect('media:uploader_dashboard')
    return render(request, 'media/confirm_delete.html', {'asset': asset})


# ── Publish (admin only) ───────────────────────────────────────────────────────

@login_required
@role_required('admin', 'super_admin')
def publish_media(request, pk):
    asset = get_object_or_404(MediaAsset, pk=pk)
    if request.method == 'POST':
        asset.status = 'published'
        asset.approved_by = request.user
        asset.published_at = timezone.now()
        asset.save(update_fields=['status', 'approved_by', 'published_at'])
        audit_log(
            action=AuditLog.Action.MEDIA_PUBLISHED,
            user=request.user,
            request=request,
            description=f'Media published: "{asset.title}" (id={asset.pk})',
            category='media',
            obj=asset,
            fields=['title', 'status', 'approved_by', 'published_at'],
        )
        messages.success(request, f'"{asset.title}" published.')
    return redirect(request.META.get('HTTP_REFERER', 'media:admin_dashboard'))
