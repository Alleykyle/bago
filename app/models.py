from django.db import models
from django.utils import timezone

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