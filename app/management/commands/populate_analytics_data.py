# Save this as: your_app/management/commands/populate_analytics_data.py

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
import random
from app.models import (
    EligibilityRequest, 
    Barangay, 
    Requirement, 
    RequirementSubmission,
    User
)

class Command(BaseCommand):
    help = 'Populate test data for analytics dashboard'

    def handle(self, *args, **kwargs):
        self.stdout.write('Creating test data...')
        
        # Get or create a test user for relationships
        test_user, created = User.objects.get_or_create(
            username='test_admin',
            defaults={
                'email': 'admin@test.com',
                'is_staff': True
            }
        )
        
        # =============================================
        # 1. Create Approved Certifications (for Graph 1)
        # =============================================
        self.stdout.write('Creating certification data...')
        
        current_year = timezone.now().year
        print(f"Creating data for year: {current_year}")
        
        months_data = [
            (1, 5), (2, 8), (3, 15), (4, 12),  # Jan-Apr
            (5, 10), (6, 7), (7, 9), (8, 14),  # May-Aug
            (9, 18), (10, 22), (11, 16), (12, 11)  # Sep-Dec
        ]
        
        for month, count in months_data:
            for i in range(count):
                # Create random date within the month
                day = random.randint(1, 28)
                date_processed = timezone.datetime(current_year, month, day)
                
                EligibilityRequest.objects.create(
                    first_name=f'Test{i}',
                    last_name=f'User{month}',
                    middle_initial='T',
                    email=f'test{i}@example.com',
                    barangay='Test Barangay',
                    position_type='elective',
                    certifier='dilg_municipality',
                    status='approved',
                    date_processed=date_processed,
                    date_submitted=date_processed - timedelta(days=7),
                    approved_by=test_user
                )
        
        self.stdout.write(self.style.SUCCESS(f'✓ Created {sum([c for _, c in months_data])} certification records'))
        
        # =============================================
        # 2. Create Barangays (for Graph 2)
        # =============================================
        self.stdout.write('Creating barangay data...')
        
        lucena_barangays = [
            ('Barangay 1', 'BRG001'),
            ('Barangay 2', 'BRG002'),
            ('Barangay 3', 'BRG003'),
            ('Barangay 4', 'BRG004'),
            ('Barangay 5', 'BRG005'),
            ('Barangay 6', 'BRG006'),
            ('Barangay 7', 'BRG007'),
            ('Barangay 8', 'BRG008'),
            ('Barangay 9', 'BRG009'),
            ('Barangay 10', 'BRG010'),
        ]
        
        barangays = []
        for name, code in lucena_barangays:
            brgy, created = Barangay.objects.get_or_create(
                code=code,
                defaults={
                    'name': name,
                    'municipality': 'Lucena'
                }
            )
            barangays.append(brgy)
        
        self.stdout.write(self.style.SUCCESS(f'✓ Created/Updated {len(barangays)} barangays'))
        
        # =============================================
        # 3. Create Requirements
        # =============================================
        self.stdout.write('Creating requirements...')
        
        requirement, created = Requirement.objects.get_or_create(
            title='Monthly Progress Report',
            defaults={
                'description': 'Monthly barangay activity report',
                'period': 'monthly',
                'is_active': True,
                'created_by': test_user
            }
        )
        
        self.stdout.write(self.style.SUCCESS('✓ Created requirement'))
        
        # =============================================
        # 4. Create Requirement Submissions (for Graph 2)
        # =============================================
        self.stdout.write('Creating submission data...')
        
        submission_count = 0
        
        for barangay in barangays:
            # Create different compliance rates for variety
            total_submissions = random.randint(8, 12)
            accomplished_rate = random.uniform(0.6, 0.95)  # 60-95% completion
            
            for i in range(total_submissions):
                # Create submission with random due date
                days_ago = random.randint(7, 90)
                due_date = timezone.now().date() - timedelta(days=days_ago)
                
                # Determine if accomplished based on rate
                is_accomplished = random.random() < accomplished_rate
                status = 'accomplished' if is_accomplished else random.choice(['pending', 'in_progress'])
                
                submission = RequirementSubmission.objects.create(
                    requirement=requirement,
                    barangay=barangay,
                    status=status,
                    due_date=due_date,
                    week_number=i + 1,
                    year=current_year,
                    update_text=f'Test update for {barangay.name}',
                )
                
                if is_accomplished:
                    # Some submissions are on-time, some are late
                    on_time = random.random() < 0.7  # 70% on-time rate
                    if on_time:
                        submission.submitted_at = due_date - timedelta(days=random.randint(0, 2))
                    else:
                        submission.submitted_at = due_date + timedelta(days=random.randint(1, 5))
                    submission.submitted_by = test_user
                    submission.save()
                
                submission_count += 1
        
        self.stdout.write(self.style.SUCCESS(f'✓ Created {submission_count} submission records'))
        
        self.stdout.write(self.style.SUCCESS('\n✅ All test data created successfully!'))
        self.stdout.write(self.style.SUCCESS('Refresh your analytics dashboard to see the graphs.'))