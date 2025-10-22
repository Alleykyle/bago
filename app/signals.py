from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta
from .models import RequirementSubmission, Notification

@receiver(post_save, sender=RequirementSubmission)
def create_submission_notifications(sender, instance, created, **kwargs):
    """Create notifications when submission status changes"""
    
    # When a new submission is created
    if created:
        if instance.barangay.submitter:
            Notification.objects.create(
                user=instance.barangay.submitter,
                type='info',
                title='New Requirement Assigned',
                message=f'You have a new requirement: {instance.requirement.title}',
                submission=instance,
                barangay=instance.barangay
            )
    
    # When submission is marked as accomplished
    elif instance.status == 'accomplished':
        # Notify all admin users
        from django.contrib.auth.models import User
        admin_users = User.objects.filter(is_staff=True)
        
        for admin in admin_users:
            # Check if notification already exists
            existing = Notification.objects.filter(
                user=admin,
                submission=instance,
                type='completed',
                created_at__gte=timezone.now() - timedelta(minutes=5)
            ).exists()
            
            if not existing:
                Notification.objects.create(
                    user=admin,
                    type='completed',
                    title='Requirement Submitted',
                    message=f'{instance.barangay.name} submitted {instance.requirement.title}',
                    submission=instance,
                    barangay=instance.barangay
                )