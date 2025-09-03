from django.shortcuts import render, redirect, get_object_or_404
from .models import Employee
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login  # <-- imported for login handling
import json
from django.contrib.auth.models import User
from django.contrib.auth import login
from .models import UserProfile
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import logout
from .decorators import role_required





def landing_page(request):
    return render(request, 'landing.html')


def logout_view(request):
    logout(request)
    messages.success(request, "You have successfully logged out.")
    return redirect('landing_page')


def login_page(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)
                try:
                    profile = user.userprofile
                    role = profile.role.strip().lower()
                    print(f"Logged in user role: {role}")  # Debug print
                except UserProfile.DoesNotExist:
                    messages.error(request, 'User profile not found. Contact admin.')
                    return redirect('login_page')

                if role == 'barangay official':
                    return redirect('civil_service_certification')
                elif role == 'municipal officer':
                    return redirect('requirements_monitoring')
                elif role == 'dilg staff':
                    return redirect('landing_menu')
                else:
                    print("Role not matched. Redirecting to landing_page")
                    return redirect('landing_page')
            else:
                messages.error(request, 'Account inactive. Please contact support.')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login_page.html')


def landing_menu(request):
    return render(request, 'landing_menu.html')

def dashboard(request):
    return render(request, 'dashboard.html')


from django.http import HttpResponseForbidden



def requirements_monitoring(request):
    return render(request, 'requirements_monitoring.html')



def application_request(request):
    return render(request, 'application_request.html')


def history(request):
    return render(request, 'history.html')


def employees_profile(request):
    if request.method == 'POST':
        # Handle adding new employee
        name = request.POST.get('name')
        id_no = request.POST.get('id_no')
        task = request.POST.get('task')
        
        # Validate required fields
        if not name or not id_no or not task:
            return JsonResponse({
                'success': False, 
                'error': 'All fields are required'
            }, status=400)
        
        try:
            # Create new employee
            Employee.objects.create(
                name=name,
                id_no=id_no,
                task=task
            )
            
            messages.success(request, 'Employee added successfully!')
            return redirect('employees_profile')
        except Exception as e:
            return JsonResponse({
                'success': False, 
                'error': str(e)
            }, status=400)
    
    # Handle GET request with search
    search_query = request.GET.get('search', '')
    employees = Employee.objects.all()
    
    if search_query:
        employees = employees.filter(
            name__icontains=search_query
        ) | employees.filter(
            id_no__icontains=search_query
        ) | employees.filter(
            task__icontains=search_query
        )
    
    return render(request, 'employees_profile.html', {
        'employees': employees,
        'search_query': search_query
    })


@require_http_methods(["POST"])
def edit_employee(request, employee_id):
    """Handle AJAX edit employee requests"""
    try:
        employee = get_object_or_404(Employee, pk=employee_id)
        
        # Parse JSON data from request body
        data = json.loads(request.body)
        
        name = data.get('name', '').strip()
        id_no = data.get('id_no', '').strip()
        task = data.get('task', '').strip()
        
        # Validate required fields
        if not name:
            return JsonResponse({
                'success': False, 
                'error': 'Name is required'
            }, status=400)
        
        if not id_no:
            return JsonResponse({
                'success': False, 
                'error': 'ID number is required'
            }, status=400)
        
        if not task:
            return JsonResponse({
                'success': False, 
                'error': 'Task assignment is required'
            }, status=400)
        
        # Check if ID number is already taken by another employee
        existing_employee = Employee.objects.filter(id_no=id_no).exclude(pk=employee_id).first()
        if existing_employee:
            return JsonResponse({
                'success': False, 
                'error': 'This ID number is already assigned to another employee'
            }, status=400)
        
        # Update employee
        employee.name = name
        employee.id_no = id_no
        employee.task = task
        employee.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Employee updated successfully'
        })
        
    except Employee.DoesNotExist:
        return JsonResponse({
            'success': False, 
            'error': 'Employee not found'
        }, status=404)
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False, 
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False, 
            'error': f'An error occurred: {str(e)}'
        }, status=500)


@require_http_methods(["DELETE"])
def delete_employee(request, employee_id):
    try:
        employee = Employee.objects.get(id=employee_id)
        employee_name = employee.name  # Store name for response
        employee.delete()
        return JsonResponse({
            'success': True,
            'message': f'Employee {employee_name} deleted successfully'
        })
    except Employee.DoesNotExist:
        return JsonResponse({
            'success': False, 
            'error': 'Employee not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False, 
            'error': f'An error occurred: {str(e)}'
        }, status=500)


def folder(request):
    return render(request, 'folder.html')

def settings(request):
    return render(request, 'settings.html')


def civil_service_certification(request):
    return render(request, 'civil_service_certification.html')


def application_letter(request):
    return render(request, 'application_letter.html')


def monitoring_filess(request):
    return render(request, 'monitoring_files.html')


def certification_filess(request):
    return render(request, 'certification_files.html')



def signup_page(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        role = request.POST.get('role')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if not all([username, email, role, password1, password2]):
            messages.error(request, 'Please fill in all fields.')
            return render(request, 'signup_page.html')

        if password1 != password2:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'signup_page.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return render(request, 'signup_page.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'signup_page.html')

        try:
            validate_password(password1)
        except ValidationError as e:
            for error in e:
                messages.error(request, error)
            return render(request, 'signup_page.html')

        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password1)

        # Create or get profile with normalized role (strip spaces)
        UserProfile.objects.get_or_create(user=user, defaults={'role': role.strip()})

        messages.success(request, 'Account created successfully. Please log in.')
        return redirect('login_page')

    return render(request, 'signup_page.html')