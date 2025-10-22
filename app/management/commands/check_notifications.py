from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Check for overdue and upcoming requirements'
    
    def handle(self, *args, **kwargs):
        from app.views import check_overdue_requirements, check_upcoming_requirements
        
        check_overdue_requirements()
        check_upcoming_requirements()
        
        self.stdout.write(self.style.SUCCESS('Successfully checked notifications'))