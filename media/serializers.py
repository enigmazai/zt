from rest_framework import serializers
from .models import MediaAsset, MediaCategory


class MediaCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model  = MediaCategory
        fields = ['id', 'name']


class MediaAssetSerializer(serializers.ModelSerializer):
    file = serializers.SerializerMethodField()
    uploaded_by_name = serializers.CharField(source='uploaded_by.full_name', read_only=True)
    category_name    = serializers.CharField(source='category.name', read_only=True, default=None)
    file_size_display = serializers.ReadOnlyField()

    def get_file(self, obj):
        return obj.delivery_url

    class Meta:
        model  = MediaAsset
        fields = [
            'id', 'title', 'description', 'file', 'thumbnail',
            'file_type', 'file_size', 'file_size_display', 'duration',
            'status', 'visibility', 'category', 'category_name',
            'tags', 'uploaded_by', 'uploaded_by_name',
            'view_count', 'created_at', 'published_at',
        ]
        read_only_fields = ['id', 'uploaded_by', 'view_count', 'created_at']
