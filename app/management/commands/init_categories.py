from django.core.management.base import BaseCommand
from app.models import FileCategory

class Command(BaseCommand):
    help = 'Initialize file categories'

    def handle(self, *args, **kwargs):
        categories = [
            {
                'name': 'certificates',
                'display_name': 'Approved Certificates',
                'folder_path': 'certificates/approved/',
                'description': 'Approved eligibility certificates',
                'icon': 'fa-certificate'
            },
            {
                'name': 'ids',
                'display_name': 'Identification Images',
                'folder_path': 'ids/',
                'description': 'Government-issued IDs',
                'icon': 'fa-id-card'
            },
            {
                'name': 'signatures',
                'display_name': 'Signatures',
                'folder_path': 'signatures/',
                'description': 'Digital signatures',
                'icon': 'fa-signature'
            },
            {
                'name': 'weekly',
                'display_name': 'Weekly Requirements',
                'folder_path': 'requirements/weekly/',
                'description': 'Weekly compliance reports',
                'icon': 'fa-calendar-week'
            },
            {
                'name': 'monthly',
                'display_name': 'Monthly Requirements',
                'folder_path': 'requirements/monthly/',
                'description': 'Monthly compliance reports',
                'icon': 'fa-calendar-alt'
            },
            {
                'name': 'quarterly',
                'display_name': 'Quarterly Requirements',
                'folder_path': 'requirements/quarterly/',
                'description': 'Quarterly compliance reports',
                'icon': 'fa-calendar'
            },
            {
                'name': 'semestral',
                'display_name': 'Semestral Requirements',
                'folder_path': 'requirements/semestral/',
                'description': 'Semestral compliance reports',
                'icon': 'fa-calendar-check'
            },
            {
                'name': 'annually',
                'display_name': 'Annual Requirements',
                'folder_path': 'requirements/annually/',
                'description': 'Annual compliance reports',
                'icon': 'fa-calendar-year'
            },
        ]
        
        for cat_data in categories:
            category, created = FileCategory.objects.get_or_create(
                name=cat_data['name'],
                defaults=cat_data
            )
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f'Created category: {category.display_name}')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'Category already exists: {category.display_name}')
                )