from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver



class Employee(models.Model):
    name = models.CharField(max_length=100)
    id_no = models.CharField(max_length=50, unique=True)
    task = models.CharField(max_length=100, blank=True, null=True, default='Unassigned')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} - {self.id_no}"
    
    class Meta:
        ordering = ['name']




class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('Barangay Official', 'Barangay Official'),
        ('Municipal Officer', 'Municipal Officer'),
        ('DILG Staff', 'DILG Staff'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=50, choices=ROLE_CHOICES)

    def __str__(self):
        return f"{self.user.username} - {self.role}"



@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance, role='')



