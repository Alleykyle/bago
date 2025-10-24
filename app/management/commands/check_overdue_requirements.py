from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta, date
from app.models import RequirementSubmission, Notification, UserProfile
from django.contrib.auth import get_user_model

User = get_user_model()

class Command(BaseCommand):
    help = 'Check for overdue and upcoming requirements and send notifications'

    def handle(self, *args, **kwargs):
        self.stdout.write('Checking for overdue and upcoming requirements...')
        
        today = date.today()
        notifications_created = 0
        
        # Get all DILG staff and municipal officers who should receive notifications
        dilg_users = User.objects.filter(
            userprofile__role__in=['dilg staff', 'municipal officer'],
            is_active=True
        )
        
        self.stdout.write(f'Found {dilg_users.count()} DILG/Municipal users to notify')
        
        # Check overdue submissions
        overdue_submissions = RequirementSubmission.objects.filter(
            due_date__lt=today,
            status__in=['pending', 'in_progress']
        ).select_related('barangay', 'requirement')
        
        self.stdout.write(f'Found {overdue_submissions.count()} overdue submissions')
        
        for submission in overdue_submissions:
            try:
                days_overdue = (today - submission.due_date).days
                
                # Get barangay officials for this specific barangay
                barangay_users = User.objects.filter(
                    userprofile__role='barangay official',
                    is_active=True
                    # Note: If you have a way to link users to specific barangays, add that filter here
                    # For example: userprofile__barangay=submission.barangay
                )
                
                # Notify barangay officials
                for user in barangay_users:
                    # Check if notification already sent today
                    existing_notif = Notification.objects.filter(
                        user=user,
                        submission=submission,
                        notification_type='overdue',
                        created_at__date=today
                    ).exists()
                    
                    if not existing_notif:
                        Notification.objects.create(
                            user=user,
                            title="⚠️ Overdue Requirement",
                            message=f"{submission.barangay.name} - {submission.requirement.title} was due on {submission.due_date.strftime('%B %d, %Y')}. Overdue by {days_overdue} day(s). Please submit as soon as possible.",
                            notification_type='overdue',
                            submission=submission
                        )
                        notifications_created += 1
                
                # Also notify DILG staff/municipal officers
                for admin in dilg_users:
                    admin_notif_exists = Notification.objects.filter(
                        user=admin,
                        submission=submission,
                        notification_type='overdue',
                        created_at__date=today
                    ).exists()
                    
                    if not admin_notif_exists:
                        Notification.objects.create(
                            user=admin,
                            title="📋 Overdue Alert",
                            message=f"{submission.barangay.name} - {submission.requirement.title} is overdue by {days_overdue} day(s)",
                            notification_type='overdue',
                            submission=submission
                        )
                        notifications_created += 1
                
                self.stdout.write(
                    self.style.WARNING(
                        f'  • Overdue ({days_overdue}d): {submission.barangay.name} - {submission.requirement.title}'
                    )
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f'  • Error processing submission {submission.id}: {e}'
                    )
                )
        
        # Check upcoming deadlines (3 days before due date)
        upcoming_date = today + timedelta(days=3)
        upcoming_submissions = RequirementSubmission.objects.filter(
            due_date=upcoming_date,
            status__in=['pending', 'in_progress']
        ).select_related('barangay', 'requirement')
        
        self.stdout.write(f'Found {upcoming_submissions.count()} upcoming deadlines (3 days)')
        
        for submission in upcoming_submissions:
            try:
                # Get barangay officials
                barangay_users = User.objects.filter(
                    userprofile__role='barangay official',
                    is_active=True
                )
                
                # Check if notification already sent
                for user in barangay_users:
                    existing_notif = Notification.objects.filter(
                        user=user,
                        submission=submission,
                        notification_type='upcoming',
                        created_at__date=today
                    ).exists()
                    
                    if not existing_notif:
                        Notification.objects.create(
                            user=user,
                            title="⏰ Upcoming Deadline",
                            message=f"{submission.barangay.name} - {submission.requirement.title} is due in 3 days ({submission.due_date.strftime('%B %d, %Y')}). Don't forget to submit!",
                            notification_type='upcoming',
                            submission=submission
                        )
                        notifications_created += 1
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f'  • Upcoming: {submission.barangay.name} - {submission.requirement.title}'
                    )
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f'  • Error processing submission {submission.id}: {e}'
                    )
                )
        
        # Check 1 day before deadline
        tomorrow = today + timedelta(days=1)
        urgent_submissions = RequirementSubmission.objects.filter(
            due_date=tomorrow,
            status__in=['pending', 'in_progress']
        ).select_related('barangay', 'requirement')
        
        self.stdout.write(f'Found {urgent_submissions.count()} urgent deadlines (tomorrow)')
        
        for submission in urgent_submissions:
            try:
                # Get barangay officials
                barangay_users = User.objects.filter(
                    userprofile__role='barangay official',
                    is_active=True
                )
                
                # Notify barangay officials
                for user in barangay_users:
                    existing_notif = Notification.objects.filter(
                        user=user,
                        submission=submission,
                        notification_type='reminder',
                        created_at__date=today
                    ).exists()
                    
                    if not existing_notif:
                        Notification.objects.create(
                            user=user,
                            title="🔔 URGENT: Due Tomorrow",
                            message=f"{submission.barangay.name} - {submission.requirement.title} is due TOMORROW ({submission.due_date.strftime('%B %d, %Y')}). Please submit today!",
                            notification_type='reminder',
                            submission=submission
                        )
                        notifications_created += 1
                
                # Also notify DILG/municipal officers about urgent items
                for admin in dilg_users:
                    admin_notif_exists = Notification.objects.filter(
                        user=admin,
                        submission=submission,
                        notification_type='reminder',
                        created_at__date=today
                    ).exists()
                    
                    if not admin_notif_exists:
                        Notification.objects.create(
                            user=admin,
                            title="⚡ Urgent Deadline Alert",
                            message=f"{submission.barangay.name} - {submission.requirement.title} is due tomorrow and still {submission.status}",
                            notification_type='reminder',
                            submission=submission
                        )
                        notifications_created += 1
                
                self.stdout.write(
                    self.style.ERROR(
                        f'  • URGENT: {submission.barangay.name} - {submission.requirement.title}'
                    )
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f'  • Error processing submission {submission.id}: {e}'
                    )
                )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'\n✓ Completed! Created {notifications_created} notifications.'
            )
        )