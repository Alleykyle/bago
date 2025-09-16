from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
import json
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.exceptions import ValidationError
from django.db.models.signals import post_save, pre_delete, post_delete
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


# Enhanced Employee model with better validation and methods
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
                                 related_name='subordinates')
    
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


# Helper function to get client IP
def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


# Add to your UserProfile model
class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('Barangay Official', 'Barangay Official'),
        ('Municipal Officer', 'Municipal Officer'),
        ('DILG Staff', 'DILG Staff'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=50, choices=ROLE_CHOICES)
    
    # Additional profile fields
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    login_count = models.PositiveIntegerField(default=0)
    is_profile_complete = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.user.username} - {self.role}"
    
    def update_login_info(self, ip_address):
        """Update login information"""
        self.last_login_ip = ip_address
        self.login_count += 1
        self.save()

from django.db import models
from django.utils import timezone

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