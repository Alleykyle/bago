from django.contrib import admin
from django.utils import timezone  
from .models import Employee, UserProfile, EligibilityRequest

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

@admin.register(EligibilityRequest)
class EligibilityRequestAdmin(admin.ModelAdmin):
    list_display = [
        'full_name', 
        'certifier', 
        'status', 
        'date_submitted', 
        'date_processed'
    ]
    
    list_filter = [
        'status', 
        'certifier', 
        'date_submitted', 
        'date_processed'
    ]
    
    search_fields = [
        'first_name', 
        'last_name', 
        'certifier'
    ]
    
    readonly_fields = [
        'date_submitted', 
        'full_name'
    ]
    
    fieldsets = (
        ('Personal Information', {
            'fields': ('first_name', 'last_name', 'middle_initial')
        }),
        ('Request Details', {
            'fields': ('certifier', 'status', 'notes', 'processed_by')
        }),
        ('Documents', {
            'fields': ('id_front', 'id_back', 'signature')
        }),
        ('Timestamps', {
            'fields': ('date_submitted', 'date_processed'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['mark_as_approved', 'mark_as_rejected', 'mark_as_processing']
    
    def mark_as_approved(self, request, queryset):
        queryset.update(status='approved', date_processed=timezone.now())
        self.message_user(request, f"{queryset.count()} requests marked as approved.")
    mark_as_approved.short_description = "Mark selected requests as approved"
    
    def mark_as_rejected(self, request, queryset):
        queryset.update(status='rejected', date_processed=timezone.now())
        self.message_user(request, f"{queryset.count()} requests marked as rejected.")
    mark_as_rejected.short_description = "Mark selected requests as rejected"
    
    def mark_as_processing(self, request, queryset):
        queryset.update(status='processing')
        self.message_user(request, f"{queryset.count()} requests marked as processing.")
    mark_as_processing.short_description = "Mark selected requests as processing"