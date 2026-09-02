import cloudinary.api
from django.core.management.base import BaseCommand

from media.models import MediaAsset


class Command(BaseCommand):
    help = 'Repair media records using Cloudinary resource metadata.'

    def handle(self, *args, **options):
        resources = []
        for resource_type in ('image', 'video', 'raw'):
            result = cloudinary.api.resources(
                type='upload',
                resource_type=resource_type,
                prefix='media_platform',
                max_results=500,
            )
            resources.extend(
                (resource_type, item)
                for item in result.get('resources', [])
            )

        changed = []
        unmatched = []
        prefixes = ('auto/upload/', 'image/upload/',
                    'video/upload/', 'raw/upload/')

        for asset in MediaAsset.objects.all():
            current = str(asset.file)
            for prefix in prefixes:
                if current.startswith(prefix):
                    current = current[len(prefix):]
                    break

            matches = [
                (resource_type, item)
                for resource_type, item in resources
                if item.get('public_id') == current
                or item.get('public_id', '').startswith(current + '.')
            ]
            if not matches:
                unmatched.append(asset.pk)
                continue

            resource_type, item = matches[0]
            asset.file = item['public_id']
            asset.file_public_id = item['public_id']
            asset.file_format = item.get('format') or ''
            asset.file_version = item.get('version')
            asset.file_type = (
                'image' if resource_type == 'image' and item.get('format') != 'pdf'
                else 'video' if resource_type == 'video'
                else 'raw'
            )
            asset.save(update_fields=[
                       'file', 'file_public_id', 'file_format', 'file_version', 'file_type'])
            changed.append(asset.pk)

        self.stdout.write(f'Changed assets: {changed}')
        self.stdout.write(f'Unmatched assets: {unmatched}')
