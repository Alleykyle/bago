from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.db.models.signals import post_save
import json
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.exceptions import ValidationError
from django.db.models.signals import post_save, pre_delete, post_delete
import threading
from django.core.mail import send_mail
from django.conf import settings
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver




@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance, role='')


class AuditLog(models.Model):
    """Track all database changes"""
    ACTION_CHOICES = [
        ('CREATE', 'Created'),
        ('UPDATE', 'Updated'),
        ('DELETE', 'Deleted'),
        ('LOGIN', 'User Login'),
        ('LOGOUT', 'User Logout'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Generic foreign key to track any model
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    
    # Store the changes as JSON
    old_values = models.JSONField(null=True, blank=True)
    new_values = models.JSONField(null=True, blank=True)
    
    # Additional context
    description = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['content_type', 'object_id']),
        ]
    
    def __str__(self):
        return f"{self.user} {self.action} {self.content_object} at {self.timestamp}"


class Employee(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('on_leave', 'On Leave'),
        ('terminated', 'Terminated'),
    ]
    
    DEPARTMENT_CHOICES = [
        ('admin', 'Administration'),
        ('hr', 'Human Resources'),
        ('finance', 'Finance'),
        ('operations', 'Operations'),
        ('it', 'Information Technology'),
    ]
    
    name = models.CharField(max_length=100)
    id_no = models.CharField(max_length=50, unique=True)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    
    # Enhanced fields
    department = models.CharField(max_length=20, choices=DEPARTMENT_CHOICES, blank=True, null=True)
    position = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='active')
    task = models.CharField(max_length=100, blank=True, null=True, default='Unassigned')
    
    # Dates
    hire_date = models.DateField(null=True, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Supervisor relationship
    supervisor = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True, 
        related_name='subordinates'
    )
    
    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['id_no']),
            models.Index(fields=['department', 'status']),
            models.Index(fields=['supervisor']),
            models.Index(fields=['status', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.name} - {self.id_no}"
    
    def clean(self):
        """Custom validation"""
        super().clean()
        
        # Validate ID format (example: must start with EMP)
        if self.id_no and not self.id_no.startswith('EMP'):
            raise ValidationError({'id_no': 'Employee ID must start with "EMP"'})
        
        # Validate email domain if provided
        if self.email and not (self.email.endswith('.gov') or self.email.endswith('.ph')):
            raise ValidationError({'email': 'Email must be a government domain (.gov or .ph)'})
    
    @property
    def years_of_service(self):
        """Calculate years of service"""
        if self.hire_date:
            from datetime import date
            today = date.today()
            return today.year - self.hire_date.year - ((today.month, today.day) < (self.hire_date.month, self.hire_date.day))
        return 0
    
    @property
    def subordinate_count(self):
        """Count direct subordinates"""
        return self.subordinates.count()
    
    def get_all_subordinates(self):
        """Get all subordinates recursively"""
        subordinates = []
        for subordinate in self.subordinates.all():
            subordinates.append(subordinate)
            subordinates.extend(subordinate.get_all_subordinates())
        return subordinates
    
    @classmethod
    def get_by_department(cls, department):
        """Get employees by department"""
        return cls.objects.filter(department=department, status='active')
    
    @classmethod
    def get_statistics(cls):
        """Get employee statistics"""
        from django.db.models import Count
        return {
            'total': cls.objects.count(),
            'active': cls.objects.filter(status='active').count(),
            'by_department': cls.objects.values('department').annotate(count=Count('id')),
            'by_status': cls.objects.values('status').annotate(count=Count('id')),
        }


# Signal handlers for audit logging
@receiver(post_save, sender=Employee)
def employee_post_save(sender, instance, created, **kwargs):
    """Log employee creation/updates"""
    action = 'CREATE' if created else 'UPDATE'
    
    # Get old values if updating
    old_values = None
    if not created and hasattr(instance, '_old_values'):
        old_values = instance._old_values
    
    # Get new values
    new_values = {
        'name': instance.name,
        'id_no': instance.id_no,
        'department': instance.department,
        'position': instance.position,
        'status': instance.status,
        'task': instance.task,
    }
    
    AuditLog.objects.create(
        action=action,
        content_object=instance,
        old_values=old_values,
        new_values=new_values,
        description=f"Employee {instance.name} was {'created' if created else 'updated'}"
    )


@receiver(pre_delete, sender=Employee)
def employee_pre_delete(sender, instance, **kwargs):
    """Store values before deletion"""
    instance._pre_delete_values = {
        'name': instance.name,
        'id_no': instance.id_no,
        'department': instance.department,
        'position': instance.position,
        'status': instance.status,
        'task': instance.task,
    }


@receiver(post_delete, sender=Employee)
def employee_post_delete(sender, instance, **kwargs):
    """Log employee deletion"""
    AuditLog.objects.create(
        action='DELETE',
        old_values=getattr(instance, '_pre_delete_values', {}),
        description=f"Employee {instance.name} was deleted"
    )


def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('barangay official', 'Barangay Official'),
        ('municipal officer', 'Municipal Officer'),
        ('dilg staff', 'DILG Staff'),
    ]



    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=50, choices=ROLE_CHOICES)

    # Extra profile fields
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    login_count = models.PositiveIntegerField(default=0)
    is_profile_complete = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {self.role.title()}"

    def update_login_info(self, ip_address):
        """Update login info after each login"""
        self.last_login_ip = ip_address
        self.login_count += 1
        self.save()

    def get_redirect_url(self):
        """Return the correct redirect path based on role"""
        mapping = {
            'barangay official': 'civil_service_certification',
            'municipal officer': 'requirements_monitoring',
            'dilg staff': 'landing_menu',
        }
        return mapping.get(self.role.lower(), 'dashboard')


class EligibilityRequest(models.Model):
    CERTIFIER_CHOICES = [
        ('punong_barangay', 'Punong Barangay'),
        ('dilg_municipality', 'DILG - Municipality'),
        ('dilg_provincial', 'DILG - Provincial'),
        ('dilg_regional', 'DILG - Regional'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('processing', 'Processing'),
    ]
    
    # Personal Information
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    middle_initial = models.CharField(max_length=5, blank=True, null=True)
    email = models.EmailField(max_length=254, blank=True, null=True) # ADD THIS LINE
    
    
    # This is the field Django is looking for
    certifier = models.CharField(max_length=50, choices=CERTIFIER_CHOICES)
    
    # File uploads
    id_front = models.ImageField(upload_to='eligibility/ids/', null=True, blank=True)
    id_back = models.ImageField(upload_to='eligibility/ids/', null=True, blank=True)
    signature = models.ImageField(upload_to='eligibility/signatures/', null=True, blank=True)
    
    # Status and dates
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    date_submitted = models.DateTimeField(default=timezone.now)
    approved_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='approved_requests'
    )
    date_processed = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-date_submitted']
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.status}"
    
    @property
    def full_name(self):
        if self.middle_initial:
            return f"{self.first_name} {self.middle_initial} {self.last_name}"
        return f"{self.first_name} {self.last_name}"
    



def send_certificate_notification_async(eligibility_request):
    """Send email notification in background thread"""
    
    def send_email_task():
        try:
            # Debug: Print what we're working with
            print(f"📧 Processing notification for request #{eligibility_request.id}")
            print(f"   Status: {eligibility_request.status}")
            print(f"   Applicant email: {eligibility_request.email}")
            
            # Determine recipient and message based on status
            if eligibility_request.status == 'pending':
                # NEW APPLICATION - Notify DILG staff
                recipient_email = settings.EMAIL_HOST_USER
                subject = '📋 New Certificate Application - Awaiting Approval'
                applicant_message = f'{eligibility_request.full_name} submitted certification, waiting for approvals.'
                print(f"   → Sending to DILG staff: {recipient_email}")
                
            else:
                # STATUS UPDATE - Notify the APPLICANT
                if not eligibility_request.email:
                    print(f"   ⚠️ No email address for request #{eligibility_request.id}, skipping notification")
                    return False
                
                recipient_email = eligibility_request.email  # Send to APPLICANT
                print(f"   → Sending to applicant: {recipient_email}")
                
                if eligibility_request.status == 'processing':
                    subject = '⏳ Certificate Application in Progress'
                    applicant_message = 'Wait for your certificate to be approved'
                    
                elif eligibility_request.status == 'approved':
                    subject = '✅ Certificate Approved - Ready to Print!'
                    applicant_message = 'Congratulations! Your certificate has been approved, you can print your eligibility certification'
                    
                elif eligibility_request.status == 'rejected':
                    subject = '❌ Certificate Application - Status Update'
                    applicant_message = 'Your certificate application has been reviewed. Unfortunately, it could not be approved at this time. Please contact DILG for more information.'
                    
                else:
                    print(f"   ⚠️ Unknown status: {eligibility_request.status}")
                    return False
            
            # Create reference number
            reference_number = f"EC-{eligibility_request.date_submitted.year}-{eligibility_request.id:03d}"
            
            # Prepare email content
            email_body = f"""
Hello,

{applicant_message}

════════════════════════════════════════
APPLICATION DETAILS
════════════════════════════════════════

 Reference Number: {reference_number}
 Applicant: {eligibility_request.full_name}
 Certifier: {eligibility_request.get_certifier_display()}
 Date Submitted: {eligibility_request.date_submitted.strftime('%B %d, %Y at %I:%M %p')}
 Current Status: {eligibility_request.get_status_display().upper()}

════════════════════════════════════════

Thank you for using the DILG Certification System.

---
DILG Lucena - Certification System
This is an automated message. Please do not reply to this email.
            """
            
            # Send the email
            send_mail(
                subject=subject,
                message=email_body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[recipient_email],
                fail_silently=False,
            )
            
            print(f"✅ Email sent successfully to {recipient_email} for request #{eligibility_request.id}")
            print(f"   Subject: {subject}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email for request #{eligibility_request.id}: {str(e)}")
            import traceback
            print(traceback.format_exc())
            return False
    
    # Start background thread
    email_thread = threading.Thread(target=send_email_task)
    email_thread.daemon = True
    email_thread.start()


@receiver(pre_save, sender=EligibilityRequest)
def track_status_change(sender, instance, **kwargs):
    """Track the old status before saving"""
    if instance.pk:  # Only for updates
        try:
            old_instance = EligibilityRequest.objects.get(pk=instance.pk)
            instance._old_status = old_instance.status
        except EligibilityRequest.DoesNotExist:
            instance._old_status = None
    else:
        instance._old_status = None


@receiver(post_save, sender=EligibilityRequest)
def notify_eligibility_status_change(sender, instance, created, **kwargs):
    """Send email notification when status changes"""
    
    # Send notification on creation (pending status)
    if created:
        print(f"🆕 New request created: #{instance.id} - Sending email to DILG...")
        send_certificate_notification_async(instance)
    
    # Send notification when status changes
    elif hasattr(instance, '_old_status') and instance._old_status != instance.status:
        print(f"🔄 Status changed for request #{instance.id}: {instance._old_status} → {instance.status}")
        print(f"   Sending email to applicant: {instance.email}")
        send_certificate_notification_async(instance)




#REQUIREMENTS MONITORING
class Barangay(models.Model):
    """Model for Barangay information"""
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=20, unique=True)
    municipality = models.CharField(max_length=100, default='Lucena')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
        verbose_name = 'Barangay'
        verbose_name_plural = 'Barangays'
    
    def __str__(self):
        return self.name


class Requirement(models.Model):
    """Model for Requirements that need to be monitored"""
    PERIOD_CHOICES = [
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('semestral', 'Semestral'),
        ('annually', 'Annually'),
    ]
    
    title = models.CharField(max_length=200)
    description = models.TextField()
    period = models.CharField(max_length=20, choices=PERIOD_CHOICES)
    
    # Applicable to which barangays (if None, applies to all)
    applicable_barangays = models.ManyToManyField(Barangay, blank=True)
    
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_requirements')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['period', 'title']
        indexes = [
            models.Index(fields=['period', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.get_period_display()})"


class RequirementSubmission(models.Model):
    """Model for tracking requirement submissions by barangays"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('accomplished', 'Accomplished'),
        ('rejected', 'Rejected'),
    ]
    
    requirement = models.ForeignKey(Requirement, on_delete=models.CASCADE, related_name='submissions')
    barangay = models.ForeignKey(Barangay, on_delete=models.CASCADE, related_name='submissions')
    
    # Submission details
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    due_date = models.DateField()
    
    # For weekly submissions - track which week
    week_number = models.PositiveIntegerField(null=True, blank=True)
    year = models.PositiveIntegerField(default=timezone.now().year)
    
    # Content
    update_text = models.TextField(blank=True)
    
    # Tracking
    submitted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='submitted_requirements')
    submitted_at = models.DateTimeField(null=True, blank=True)
    
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_requirements')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['barangay', 'status']),
            models.Index(fields=['requirement', 'due_date']),
            models.Index(fields=['week_number', 'year']),
        ]
        unique_together = [['requirement', 'barangay', 'week_number', 'year']]
    
    def __str__(self):
        return f"{self.requirement.title} - {self.barangay.name} - Week {self.week_number}"
    
    @property
    def is_overdue(self):
        """Check if submission is overdue"""
        if self.status in ['accomplished', 'rejected']:
            return False
        return timezone.now().date() > self.due_date
    
    def submit(self, user):
        """Mark as submitted"""
        self.status = 'in_progress'
        self.submitted_by = user
        self.submitted_at = timezone.now()
        self.save()
        
        # Log the submission
        AuditLog.objects.create(
            user=user,
            action='CREATE',
            content_object=self,
            description=f"Submitted requirement: {self.requirement.title} for {self.barangay.name}"
        )


class RequirementAttachment(models.Model):
    """Model for file attachments (images/documents) for requirements"""
    submission = models.ForeignKey(RequirementSubmission, on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(upload_to='requirements/%Y/%m/')
    file_type = models.CharField(max_length=50)  # image/jpeg, application/pdf, etc.
    file_size = models.PositiveIntegerField()  # in bytes
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return f"Attachment for {self.submission}"
    
    @property
    def file_size_kb(self):
        """Return file size in KB"""
        return round(self.file_size / 1024, 2)
    
    def delete(self, *args, **kwargs):
        """Delete file when model is deleted"""
        if self.file:
            self.file.delete(save=False)
        super().delete(*args, **kwargs)


@receiver(pre_save, sender=RequirementSubmission)
def track_submission_status_change(sender, instance, **kwargs):
    """Track the old status before saving"""
    if instance.pk:
        try:
            old_instance = RequirementSubmission.objects.get(pk=instance.pk)
            instance._old_status = old_instance.status
        except RequirementSubmission.DoesNotExist:
            instance._old_status = None
    else:
        instance._old_status = None


@receiver(post_save, sender=RequirementSubmission)
def log_submission_status_change(sender, instance, created, **kwargs):
    """Log status changes"""
    if created:
        AuditLog.objects.create(
            action='CREATE',
            content_object=instance,
            description=f"New requirement submission: {instance.requirement.title} for {instance.barangay.name}"
        )
    elif hasattr(instance, '_old_status') and instance._old_status != instance.status:
        AuditLog.objects.create(
            action='UPDATE',
            content_object=instance,
            old_values={'status': instance._old_status},
            new_values={'status': instance.status},
            description=f"Status changed: {instance.requirement.title} - {instance._old_status} → {instance.status}"
        )




class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('overdue', 'Overdue'),
        ('upcoming', 'Upcoming'),
        ('completed', 'Completed'),
        ('reminder', 'Reminder'),
        ('info', 'Information'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES, default='info')
    title = models.CharField(max_length=200)
    message = models.TextField()
    submission = models.ForeignKey('RequirementSubmission', on_delete=models.CASCADE, null=True, blank=True)
    barangay = models.ForeignKey('Barangay', on_delete=models.CASCADE, null=True, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.username} - {self.title}"
    
    def time_ago(self):
        """Return human-readable time difference"""
        now = timezone.now()
        diff = now - self.created_at
        
        if diff.days > 365:
            years = diff.days // 365
            return f"{years} year{'s' if years > 1 else ''} ago"
        elif diff.days > 30:
            months = diff.days // 30
            return f"{months} month{'s' if months > 1 else ''} ago"
        elif diff.days > 0:
            return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else:
            return "Just now"
        
class Announcement(models.Model):
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    
    title = models.CharField(max_length=200)
    content = models.TextField()
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='medium')
    posted_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='announcements')
    posted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    views = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-posted_at']
    
    def __str__(self):
        return self.title
    
    def increment_views(self):
        self.views += 1
        self.save(update_fields=['views'])