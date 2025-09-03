from django.urls import path
from . import views

urlpatterns = [
    path('', views.landing_page, name='landing_page'),
    path('login/', views.login_page, name='login_page'),
    path('landing_menu/', views.landing_menu, name='landing_menu'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('requirements_monitoring/', views.requirements_monitoring, name='requirements_monitoring'),
    path('application_request/', views.application_request, name='application_request'),
    path('history/', views.history, name='history'),
    path('signup/', views.signup_page, name='signup_page'),
    path('logout/', views.logout_view, name='logout'),
    
    # Employee management URLs
    path('employees_profile/', views.employees_profile, name='employees_profile'),
    path('edit-employee/<int:employee_id>/', views.edit_employee, name='edit_employee'),
    path('delete-employee/<int:employee_id>/', views.delete_employee, name='delete_employee'),
    
    path('folder/', views.folder, name='folder'),
    path('settings/', views.settings, name='settings'),
    path('civil_service_certification/', views.civil_service_certification, name='civil_service_certification'),
    path('application_letter/', views.application_letter, name='application_letter'),
    path('monitoring_filess/', views.monitoring_filess, name='monitoring_filess'),
    path('certification_filess/', views.certification_filess, name='certification_filess'),


]