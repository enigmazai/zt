from django.db import models
from django.conf import settings
from cloudinary.models import CloudinaryField


class MediaCategory(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = 'Media Categories'
        ordering = ['name']

    def __str__(self): return self.name


class MediaAsset(models.Model):
    class Status(models.TextChoices):
        DRAFT = 'draft',     'Draft'
        PUBLISHED = 'published', 'Published'
        ARCHIVED = 'archived',  'Archived'

    class Visibility(models.TextChoices):
        PUBLIC = 'public',   'Public'
        INTERNAL = 'internal', 'Internal (logged in only)'
        PRIVATE = 'private',  'Private (uploader/admin only)'

    # Identity
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    category = models.ForeignKey(
        MediaCategory, null=True, blank=True, on_delete=models.SET_NULL)
    tags = models.CharField(max_length=500, blank=True,
                            help_text='Comma-separated tags')

    # File (stored in Cloudinary)
    file = CloudinaryField('file', resource_type='auto', blank=True, null=True)
    file_public_id = models.CharField(max_length=255, blank=True)
    file_format = models.CharField(max_length=20, blank=True)
    file_version = models.PositiveBigIntegerField(null=True, blank=True)
    thumbnail = CloudinaryField('image', blank=True, null=True)
    # video, image, audio, document
    file_type = models.CharField(max_length=50, blank=True)
    file_size = models.PositiveBigIntegerField(default=0)      # bytes
    duration = models.FloatField(
        null=True, blank=True)       # seconds (video/audio)

    # Access control
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.DRAFT)
    visibility = models.CharField(
        max_length=20, choices=Visibility.choices, default=Visibility.INTERNAL)

    # Ownership
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='uploads',
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='approved_media',
    )

    # Meta
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)
    view_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self): return self.title

    @property
    def tag_list(self):
        return [t.strip() for t in self.tags.split(',') if t.strip()]

    @property
    def delivery_url(self):
        """Return a Cloudinary delivery URL with a valid resource type."""
        if not self.file:
            return ''

        try:
            from cloudinary.utils import cloudinary_url
            return cloudinary_url(
                self._cloudinary_public_id,
                resource_type=self._cloudinary_resource_type,
                format=self.file_format or None,
                version=self.file_version,
                secure=True,
                sign_url=False,
            )[0]
        except Exception:
            return ''

    @property
    def download_url(self):
        """Return a signed Cloudinary URL that downloads the asset as a file."""
        if not self.file:
            return ''

        try:
            from cloudinary.utils import cloudinary_url
            return cloudinary_url(
                self._cloudinary_public_id,
                resource_type=self._cloudinary_resource_type,
                format=self.file_format or None,
                version=self.file_version,
                secure=True,
                sign_url=False,
            )[0]
        except Exception:
            return ''

    @property
    def _cloudinary_resource_type(self):
        return {
            'image': 'image',
            'video': 'video',
            # Cloudinary delivers audio through its video resource type.
            'audio': 'video',
            'raw': 'raw',
            'document': 'raw',
        }.get(self.file_type, 'raw')

    @property
    def _cloudinary_public_id(self):
        public_id = self.file_public_id or getattr(
            self.file, 'public_id', None) or str(self.file)
        # Older uploads can contain Cloudinary's delivery prefix in the value.
        for prefix in ('auto/upload/', 'image/upload/', 'video/upload/', 'raw/upload/'):
            if public_id.startswith(prefix):
                return public_id[len(prefix):]
        return public_id

    @property
    def file_size_display(self):
        if self.file_size < 1024:
            return f'{self.file_size} B'
        elif self.file_size < 1024 ** 2:
            return f'{self.file_size / 1024:.1f} KB'
        elif self.file_size < 1024 ** 3:
            return f'{self.file_size / 1024**2:.1f} MB'
        return f'{self.file_size / 1024**3:.2f} GB'

    def can_view(self, user):
        if self.visibility == self.Visibility.PUBLIC:
            return True
        if not user.is_authenticated:
            return False
        if self.visibility == self.Visibility.INTERNAL:
            return True
        # PRIVATE: only uploader or admin
        return user == self.uploaded_by or user.is_admin

    def can_edit(self, user):
        return user == self.uploaded_by or user.is_admin

    def can_delete(self, user):
        return user.is_admin or user == self.uploaded_by
