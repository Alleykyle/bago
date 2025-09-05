from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from app.models import AuditLog  

class Command(BaseCommand):
    help = 'Clean up old activity logs to prevent database bloat'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=365,
            help='Number of days to keep (default: 365)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )
        parser.add_argument(
            '--keep-security',
            action='store_true',
            help='Always keep security-related logs regardless of age'
        )

    def handle(self, *args, **options):
        days_to_keep = options['days']
        dry_run = options['dry_run']
        keep_security = options['keep_security']
        
        cutoff_date = timezone.now() - timedelta(days=days_to_keep)
        
        # Base queryset for old logs
        old_logs = AuditLog.objects.filter(timestamp__lt=cutoff_date)
        
        # Exclude security logs if requested
        if keep_security:
            security_actions = ['SECURITY_ALERT', 'LOGIN_FAILED', 'UNAUTHORIZED_ACCESS']
            old_logs = old_logs.exclude(action__in=security_actions)
        
        count = old_logs.count()
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(f'DRY RUN: Would delete {count} activity logs older than {days_to_keep} days')
            )
            
            # Show breakdown by action type
            from django.db.models import Count
            breakdown = old_logs.values('action').annotate(count=Count('id')).order_by('-count')
            
            self.stdout.write('\nBreakdown by action type:')
            for item in breakdown:
                self.stdout.write(f"  {item['action']}: {item['count']}")
        
        else:
            if count == 0:
                self.stdout.write(self.style.SUCCESS('No old activity logs to delete'))
                return
            
            # Delete in batches to avoid memory issues
            batch_size = 1000
            deleted_total = 0
            
            while old_logs.exists():
                batch_ids = list(old_logs.values_list('id', flat=True)[:batch_size])
                deleted_count = AuditLog.objects.filter(id__in=batch_ids).delete()[0]
                deleted_total += deleted_count
                
                self.stdout.write(f'Deleted {deleted_total}/{count} logs...', ending='\r')
            
            self.stdout.write(
                self.style.SUCCESS(f'\nSuccessfully deleted {deleted_total} activity logs older than {days_to_keep} days')
            )
            
            # Log the cleanup activity
            try:
                AuditLog.objects.create(
                    action='MAINTENANCE',
                    description=f'Cleaned up {deleted_total} old activity logs (older than {days_to_keep} days)',
                    new_values={
                        'deleted_count': deleted_total,
                        'cutoff_date': cutoff_date.isoformat(),
                        'kept_security_logs': keep_security
                    }
                )
            except:
                pass  # Don't fail if logging the cleanup fails

