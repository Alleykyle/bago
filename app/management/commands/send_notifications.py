from django.core.management.base import BaseCommand
from app.tasks import check_overdue_requirements, check_upcoming_requirements

class Command(BaseCommand):
    help = 'Check and send notifications for overdue and upcoming requirements'
    
    def handle(self, *args, **kwargs):
        self.stdout.write('Checking for overdue requirements...')
        overdue_count = check_overdue_requirements()
        self.stdout.write(self.style.SUCCESS(f'Created {overdue_count} overdue notifications'))
        
        self.stdout.write('Checking for upcoming requirements...')
        upcoming_count = check_upcoming_requirements()
        self.stdout.write(self.style.SUCCESS(f'Created {upcoming_count} upcoming notifications'))
        
        self.stdout.write(self.style.SUCCESS('✓ Notification check completed'))