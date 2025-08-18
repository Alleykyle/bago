from django.shortcuts import render, redirect, get_object_or_404
from .models import Employee
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import json


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