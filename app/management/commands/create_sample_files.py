from django.core.management.base import BaseCommand
from app.models import MonitoringFile, Barangay
from django.core.files.base import ContentFile
from django.utils import timezone
import random

class Command(BaseCommand):
    help = 'Create sample monitoring files for testing'

    def handle(self, *args, **options):
        self.stdout.write('Creating sample monitoring files...')
        
        # Get all barangays
        barangays = list(Barangay.objects.all())
        
        if not barangays:
            self.stdout.write(self.style.ERROR('No barangays found! Create barangays first.'))
            return
        
        categories = ['weekly', 'monthly', 'quarterly', 'semestral', 'annually']
        
        created_count = 0
        
        for category in categories:
            # Create 5 sample files per category
            for i in range(5):
                barangay = random.choice(barangays)
                
                # Create a dummy file
                dummy_content = f"Sample {category} file {i+1} for {barangay.name}"
                file_content = ContentFile(dummy_content.encode())
                
                monitoring_file = MonitoringFile.objects.create(
                    filename=f"sample_{category}_{i+1}.txt",
                    category=category,
                    barangay=barangay,
                    uploaded_at=timezone.now()
                )
                
                # Save the file content
                monitoring_file.file.save(
                    f"sample_{category}_{i+1}.txt",
                    file_content,
                    save=True
                )
                
                created_count += 1
                self.stdout.write(f"Created: {monitoring_file.filename} for {barangay.name}")
        
        self.stdout.write(self.style.SUCCESS(f'Successfully created {created_count} sample files'))