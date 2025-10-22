from django.urls import path
from . import views

urlpatterns = [
    # ============================================
    # PUBLIC PAGES
    # ============================================
    path('', views.landing_page, name='landing_page'),
    path('login/', views.login_page, name='login_page'),
    path('signup/', views.signup_page, name='signup_page'),
    path('logout/', views.logout_view, name='logout'),
    
    # ============================================
    # BARANGAY OFFICIAL - SUBMISSION PAGES
    # ============================================
    path('requirements_monitoring/', views.requirements_monitoring, name='requirements_monitoring'),
    path('civil_service_certification/', views.civil_service_certification, name='civil_service_certification'),
    
    # ============================================
    # DILG ADMIN - REVIEW PAGES (Changed path!)
    # ============================================
    # ✅ Changed from /admin/submissions/ to /dilg/submissions/
    path('dilg/submissions/', views.admin_submissions_page, name='admin_submissions_page'),
    path('dilg/application-requests/', views.application_request, name='application_request'),
    
    # ============================================
    # DILG STAFF DASHBOARD
    # ============================================
    path('landing-menu/', views.landing_menu, name='landing_menu'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('employees/', views.employees_profile, name='employees_profile'),
    path('history/', views.history, name='history'),
    path('analytics/', views.analytics_dashboard, name='analytics_dashboard'),
    
    # ============================================
    # API ENDPOINTS - REQUIREMENTS MONITORING
    # ============================================
    path('api/requirements/list/', views.api_requirements_list, name='api_requirements_list'),
    path('api/barangay/<int:barangay_id>/status/', views.get_barangay_status, name='barangay_status'),
    path('api/requirements/submission/<int:submission_id>/', views.api_submission_detail, name='api_submission_detail'),
    path('api/requirements/submission/<int:submission_id>/update/', views.api_submission_update, name='api_submission_update'),
    path('api/requirements/submission/<int:submission_id>/submit/', views.api_submission_submit, name='api_submission_submit'),
    path('api/requirements/submission/<int:submission_id>/delete/', views.api_submission_delete, name='api_submission_delete'),
    path('api/requirements/attachment/upload/', views.api_attachment_upload, name='api_attachment_upload'),
    path('api/requirements/attachment/<int:attachment_id>/delete/', views.api_attachment_delete, name='api_attachment_delete'),
    path('api/requirements/list/', views.get_requirements_list, name='requirements_list'),
    path('api/requirements/submission/<int:submission_id>/', views.get_submission_detail, name='submission_detail'),
    
    # ============================================
    # API ENDPOINTS - DILG ADMIN REVIEW
    # ============================================
    path('api/admin/submissions/', views.api_admin_submissions_list, name='api_admin_submissions_list'),
    path('api/admin/review/<int:submission_id>/', views.api_admin_review_submission, name='api_admin_review_submission'),
    
    # ============================================
    # API ENDPOINTS - ELIGIBILITY REQUESTS
    # ============================================
    path('api/eligibility/submit/', views.submit_eligibility_request, name='submit_eligibility_request'),
    path('api/eligibility/update-status/', views.update_application_status, name='update_application_status'),
    
    # ============================================
    # API ENDPOINTS - EMPLOYEES
    # ============================================
    path('api/employees/edit/<int:employee_id>/', views.edit_employee, name='edit_employee'),
    path('api/employees/delete/<int:employee_id>/', views.delete_employee, name='delete_employee'),
    path('api/employees/export/', views.export_employees, name='export_employees'),
    path('api/employees/search/', views.employee_search_api, name='employee_search_api'),
    path('api/employees/bulk/', views.bulk_employee_operations, name='bulk_employee_operations'),
    
    # ============================================
    # API ENDPOINTS - HISTORY
    # ============================================
    path('api/history/', views.history_api, name='history_api'),
    path('api/history/export/', views.export_history, name='export_history'),
    path('api/history/bulk/', views.bulk_history_operations, name='bulk_history_operations'),
    path('api/history/stats/', views.activity_stats, name='activity_stats'),
    
    # ============================================
    # OTHER PAGES
    # ============================================
    path('folder/', views.folder, name='folder'),
    path('settings/', views.settings, name='settings'),
    path('application-letter/', views.application_letter, name='application_letter'),
    path('monitoring-files/', views.monitoring_filess, name='monitoring_filess'),
    path('certification-files/', views.certification_filess, name='certification_filess'),

    # ============================================
    # API ENDPOINTS - DILG ADMIN REVIEW (FIXED PATH!)
    # ============================================
    path('api/admin/submissions/', views.api_admin_submissions_list, name='api_admin_submissions_list'),
    path('api/admin/review/<int:submission_id>/', views.api_admin_review_submission, name='api_admin_review_submission'),
    
    # ============================================
    # API ENDPOINTS - DILG REQUIREMENT MANAGEMENT
    # ============================================
    path('api/requirements/create/', views.api_create_requirement, name='api_create_requirement'),
    path('api/requirements/<int:requirement_id>/edit/', views.api_edit_requirement, name='api_edit_requirement'),
    path('api/requirements/<int:requirement_id>/delete/', views.api_delete_requirement, name='api_delete_requirement'),
    path('api/requirements/all/', views.api_all_requirements, name='api_all_requirements'),

    # Notification endpoints
    path('api/notifications/', views.get_notifications, name='get_notifications'),
    path('api/notifications/<int:notification_id>/read/', views.mark_notification_read, name='mark_notification_read'),
    path('api/notifications/mark-all-read/', views.mark_all_notifications_read, name='mark_all_notifications_read'),
    path('notifications/', views.notifications_page, name='notifications_page'),
]