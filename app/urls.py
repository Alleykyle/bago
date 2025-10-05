
from django.urls import path
from . import views

urlpatterns = [
    # ... your existing URL patterns ...
    path('', views.landing_page, name='landing_page'),
    path('login/', views.login_page, name='login_page'),
    path('landing_menu/', views.landing_menu, name='landing_menu'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('requirements_monitoring/', views.requirements_monitoring, name='requirements_monitoring'),
    path('application_request/', views.application_request, name='application_request'),
     path('csc/', views.civil_service_certification, name='civi_service_certification'),
    
    # Enhanced History URLs
    path('history/', views.history, name='history'),
    path('history/api/', views.history_api, name='history_api'),
    path('history/export/', views.export_history, name='export_history'),
    path('history/bulk/', views.bulk_history_operations, name='bulk_history_operations'),
    
    # Activity Statistics
    path('activity-stats/', views.activity_stats, name='activity_stats'),
    
    path('signup/', views.signup_page, name='signup_page'),
    path('logout/', views.logout_view, name='logout'),
    
    # Employee management URLs
    path('employees_profile/', views.employees_profile, name='employees_profile'),
    path('edit-employee/<int:employee_id>/', views.edit_employee, name='edit_employee'),
    path('delete-employee/<int:employee_id>/', views.delete_employee, name='delete_employee'),
    path('export-employees/', views.export_employees, name='export_employees'),
    path('bulk-employee-operations/', views.bulk_employee_operations, name='bulk_employee_operations'),
    
    path('folder/', views.folder, name='folder'),
    path('settings/', views.settings, name='settings'),
    path('civil_service_certification/', views.civil_service_certification, name='civil_service_certification'),
    path('application_letter/', views.application_letter, name='application_letter'),
    path('monitoring_filess/', views.monitoring_filess, name='monitoring_filess'),
    path('certification_filess/', views.certification_filess, name='certification_filess'),

    path('refresh-analytics/', views.refresh_analytics, name='refresh_analytics'),
    path('analytics_dashboard/', views.analytics_dashboard, name='analytics_dashboard'),
    path('employee-search-api/', views.employee_search_api, name='employee_search_api'),

    # Public form for citizens
    path('civil_service_certification/', views.civil_service_certification, name='civil_service_certification'),
    
    # Form submission endpoint
    path('submit_eligibility_request/', views.submit_eligibility_request, name='submit_eligibility_request'),
    
    # Admin dashboard
    path('application_request/', views.application_request, name='application_request'),
    
    # Status update endpoint
    path('update_application_status/', views.update_application_status, name='update_application_status'),
]

