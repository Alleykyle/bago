
from django.contrib import admin
from django.urls import path



from django.shortcuts import render

def landing_page(request):
    return render(request, 'landing.html')

def login_page(request):
    return render(request, 'login_page.html')

def landing_menu(request):
    return render(request, 'landing_menu.html')

def dashboard(request):
    return render(request, 'dashboard.html')

def requirements_monitoring(request):
    return render(request, 'requirements_monitoring.html')

def application_request(request):
    return render(request, 'application_request.html')

def history(request):
    return render(request, 'history.html')

def employees_profile(request):
    return render(request, 'employees_profile.html')

def folder(request):
    return render(request, 'folder.html')

def settings(request):
    return render(request, 'settings.html')

def civil_service_certification(request):
    return render(request, 'civil_service_certification.html')

def application_letter(request):
    return render(request, 'application_letter.html')

def valid_id(request):
    return render(request, 'valid_id.html')

urlpatterns = [
    path('', landing_page, name='landing'),
    path('login/', login_page, name='login_page'),
    path('menu/', landing_menu, name='landing_menu'),
    path('dashboard/', dashboard, name='dashboard.html'),
    path('requirements_monitoring/', requirements_monitoring, name='requirements_monitoring.html'),
    path('application_request/', application_request, name='application_request.html'),
    path('history/', history, name='history.html'),
    path('employees_profile/', employees_profile, name='employees_profile.html'),
    path('folder/', folder, name='folder.html'),
    path('settings/', settings, name='settings.html'),
    path('civil_service_certification/', civil_service_certification, name='civil_service_certification.html'),
    path('application_letter/', application_letter, name='application_letter.html'),
    path('valid_id/', valid_id, name='valid_id.html'),
    
    
]

