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