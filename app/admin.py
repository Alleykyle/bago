from django.contrib import admin
from .models import Employee, UserProfile

@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    list_display = ['name', 'id_no', 'task', 'created_at', 'updated_at']
    list_filter = ['task', 'created_at']
    search_fields = ['name', 'id_no']
    list_editable = ['task']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Employee Information', {
            'fields': ('name', 'id_no', 'task')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'role']
    list_filter = ['role']
    search_fields = ['user__username', 'user__email']