from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import User
from .models import RequirementSubmission, Notification

@receiver(post_save, sender=RequirementSubmission)
def create_submission_notifications(sender, instance, created, **kwargs):
    """
    Create notifications when submission status changes
    """
    try:
        # Only create notifications for status changes (not on creation)
        if created:
            return
        
        # Check if status changed to 'accomplished' (submitted)
        if instance.status == 'accomplished' and instance.submitted_at:
            # Notify DILG admins
            admin_users = User.objects.filter(
                userprofile__role='dilg staff',
                is_active=True
            ).distinct()
            
            for admin in admin_users:
                # Check if notification already exists (prevent duplicates)
                existing = Notification.objects.filter(
                    user=admin,
                    submission=instance,
                    notification_type='info',  # ✅ FIXED: was 'type'
                    created_at__gte=timezone.now() - timedelta(minutes=5)
                ).exists()
                
                if not existing:
                    Notification.objects.create(
                        user=admin,
                        title="New Submission for Review",
                        message=f"{instance.barangay.name} submitted: {instance.requirement.title}",
                        notification_type='info',  # ✅ FIXED: was 'type'
                        submission=instance
                    )
        
        # Check if status changed to 'approved' or 'rejected'
        elif instance.status in ['approved', 'rejected']:
            if instance.submitted_by:
                # Notify the submitter
                existing = Notification.objects.filter(
                    user=instance.submitted_by,
                    submission=instance,
                    notification_type='completed' if instance.status == 'approved' else 'overdue',  # ✅ FIXED
                    created_at__gte=timezone.now() - timedelta(minutes=5)
                ).exists()
                
                if not existing:
                    status_emoji = "✅" if instance.status == 'approved' else "❌"
                    status_text = "approved" if instance.status == 'approved' else "needs revision"
                    
                    Notification.objects.create(
                        user=instance.submitted_by,
                        title=f"{status_emoji} Submission {status_text.title()}",
                        message=f"Your submission '{instance.requirement.title}' has been {status_text}",
                        notification_type='completed' if instance.status == 'approved' else 'overdue',  # ✅ FIXED
                        submission=instance
                    )
    
    except Exception as e:
        # Log error but don't break the save operation
        print(f"Error creating notification: {e}")
        import traceback
        print(traceback.format_exc())