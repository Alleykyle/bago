from django.shortcuts import render, redirect, get_object_or_404
from .models import Employee
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout
import json
from django.contrib.auth.models import User
from .models import UserProfile
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from .decorators import role_required
from django.db.models import Q, Count, Avg, Sum
from django.db import transaction, connection
from django.core.paginator import Paginator
from django.core.cache import cache
from django.http import HttpResponse, HttpResponseForbidden
import csv
import openpyxl
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Q, Count, Avg, Sum  
from .models import EligibilityRequest, Barangay, Requirement, RequirementSubmission, RequirementAttachment, Notification, Announcement
from django.views.decorators.http import require_POST
import os
from datetime import date
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from datetime import timedelta
import traceback


try:
    from .models import AuditLog
except ImportError:
    class AuditLog:
        @staticmethod
        def objects():
            return None
        
        @staticmethod
        def create(**kwargs):
            pass


def get_client_ip(request):
    """Helper function to get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def landing_page(request):
    return render(request, 'landing.html')


def logout_view(request):
    if request.user.is_authenticated:
        try:
            AuditLog.objects.create(
                user=request.user,
                action='LOGOUT',
                ip_address=get_client_ip(request),
                description=f"User {request.user.username} logged out"
            )
        except:
            pass  # Skip audit logging if AuditLog doesn't exist
    
    logout(request)
    messages.success(request, "You have successfully logged out.")
    return redirect('landing_page')


def login_page(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')

        if user is not None:
            login(request, user)
            profile, created = UserProfile.objects.get_or_create(user=user)
            profile.update_login_info(ip_address)

            AuditLog.objects.create(
                user=user,
                action='LOGIN',
                ip_address=ip_address,
                user_agent=user_agent,
                description=f"{user.username} logged in as {profile.role}",
            )

            # 🧠 Debug
            print("🔍 ROLE DETECTED:", profile.role)
            print("🔍 REDIRECTING TO:", profile.get_redirect_url())

            redirect_url = profile.get_redirect_url()
            messages.success(request, f"Welcome back, {user.username}!")
            return redirect(redirect_url)

        else:
            messages.error(request, "Invalid username or password.")

    return render(request, 'login_page.html')


@login_required
def logout_view(request):
    """Handle user logout with audit log"""
    user = request.user
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')

    # Log the logout action
    AuditLog.objects.create(
        user=user,
        action='LOGOUT',
        ip_address=ip_address,
        user_agent=user_agent,
        description=f"{user.username} logged out",
    )

    logout(request)
    messages.info(request, "You have been logged out successfully.")
    return redirect('login')  # change to your login page URL name


def landing_menu(request):
    return render(request, 'landing_menu.html')



def dashboard(request):
    """
    Safe Analytics Dashboard View - No attribute errors
    """
    try:
        # Basic Employee Statistics - These should always work
        total_employees = Employee.objects.count()
        active_employees = Employee.objects.filter(status='active').count()
        
        # Simple stats that don't depend on unknown fields
        context = {
            'total_employees': total_employees,
            'active_employees': active_employees,
            'new_employees_30d': 0,  # We'll calculate this safely later
            'dept_stats': [],  # Empty for now
            'task_stats': [],  # Empty for now
            'user_activity': [],  # Empty for now
            'recent_activities': [],  # Empty for now
            'table_stats': [('Employees', total_employees)],
            'db_size': None,
        }
        
        print(f"Dashboard stats: Total={total_employees}, Active={active_employees}")
        return render(request, 'dashboard.html', context)
        
    except Exception as e:
        print(f"Dashboard error: {e}")
        # Return safe empty context
        context = {
            'total_employees': 0,
            'active_employees': 0,
            'new_employees_30d': 0,
            'dept_stats': [],
            'task_stats': [],
            'user_activity': [],
            'recent_activities': [],
            'table_stats': [],
            'db_size': None,
        }
        return render(request, 'dashboard.html', context)


@login_required
def refresh_analytics(request):
    """
    Safe AJAX endpoint to refresh analytics data
    """
    if request.method == 'GET':
        try:
            total_employees = Employee.objects.count()
            active_employees = Employee.objects.filter(status='active').count()
            
            return JsonResponse({
                'success': True,
                'data': {
                    'total_employees': total_employees,
                    'active_employees': active_employees,
                    'timestamp': timezone.now().strftime('%B %d, %H:%M')
                }
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})


# DEBUG VIEW - Add this temporarily to see your model structure
@login_required 
def debug_employee(request):
    """
    Debug view to inspect Employee model
    """
    try:
        # Get first employee
        emp = Employee.objects.first()
        
        # Get all field names
        field_names = [f.name for f in Employee._meta.fields]
        
        # Get sample data safely
        sample_data = {}
        if emp:
            for field_name in field_names:
                try:
                    value = getattr(emp, field_name, 'N/A')
                    sample_data[field_name] = str(value)[:100]  # Limit length
                except:
                    sample_data[field_name] = 'Error reading'
        
        return JsonResponse({
            'total_employees': Employee.objects.count(),
            'field_names': field_names,
            'sample_data': sample_data
        }, indent=2)
        
    except Exception as e:
        return JsonResponse({'error': str(e)})



def application_request(request):
    return render(request, 'application_request.html')


def history(request):
    return render(request, 'history.html')

@login_required
def history_api(request):
    """AJAX endpoint for history page real-time updates"""
    if not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'error': 'Invalid request'}, status=400)
    
    try:
        # Get the last activity ID from the request to check for new activities
        last_activity_id = request.GET.get('last_id', 0)
        
        # Check if there are new activities since the last check
        new_activities_count = AuditLog.objects.filter(id__gt=last_activity_id).count()
        
        # Get activity statistics
        today = timezone.now().date()
        stats = {
            'total_activities': AuditLog.objects.count(),
            'today_activities': AuditLog.objects.filter(timestamp__date=today).count(),
            'unique_users': AuditLog.objects.exclude(user__isnull=True).values('user').distinct().count(),
            'action_types': AuditLog.objects.values('action').distinct().count(),
            'has_new_activities': new_activities_count > 0,
            'new_activities_count': new_activities_count
        }
        
        return JsonResponse({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
    
@login_required
def export_history(request):
    """Export history data as CSV or Excel"""
    try:
        format_type = request.GET.get('format', 'csv')
        
        # Apply same filters as history view
        activities = AuditLog.objects.select_related('user', 'content_type').order_by('-timestamp')
        
        # Apply filters
        action_filter = request.GET.get('action', '')
        user_filter = request.GET.get('user', '')
        date_from = request.GET.get('date_from', '')
        date_to = request.GET.get('date_to', '')
        search_query = request.GET.get('search', '')
        
        if action_filter:
            activities = activities.filter(action=action_filter)
        
        if user_filter:
            activities = activities.filter(user__username__icontains=user_filter)
        
        if date_from:
            activities = activities.filter(timestamp__date__gte=date_from)
        
        if date_to:
            activities = activities.filter(timestamp__date__lte=date_to)
        
        if search_query:
            activities = activities.filter(
                Q(description__icontains=search_query) |
                Q(user__username__icontains=search_query) |
                Q(action__icontains=search_query)
            )
        
        # Limit export to prevent performance issues
        activities = activities[:5000]  # Max 5000 records
        
        if format_type == 'excel':
            import openpyxl
            from openpyxl.styles import Font, Alignment
            
            response = HttpResponse(
                content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
            response['Content-Disposition'] = f'attachment; filename="activity_history_{timezone.now().strftime("%Y%m%d_%H%M")}.xlsx"'
            
            workbook = openpyxl.Workbook()
            worksheet = workbook.active
            worksheet.title = 'Activity History'
            
            # Headers
            headers = [
                'ID', 'User', 'Action', 'Description', 'Timestamp', 
                'IP Address', 'Content Type', 'Object ID', 'Old Values', 'New Values'
            ]
            
            # Style headers
            header_font = Font(bold=True)
            header_alignment = Alignment(horizontal='center')
            
            for col, header in enumerate(headers, 1):
                cell = worksheet.cell(row=1, column=col, value=header)
                cell.font = header_font
                cell.alignment = header_alignment
            
            # Data rows
            for row, activity in enumerate(activities, 2):
                worksheet.cell(row=row, column=1, value=activity.id)
                worksheet.cell(row=row, column=2, value=activity.user.username if activity.user else 'System')
                worksheet.cell(row=row, column=3, value=activity.action)
                worksheet.cell(row=row, column=4, value=activity.description)
                worksheet.cell(row=row, column=5, value=activity.timestamp.strftime('%Y-%m-%d %H:%M:%S'))
                worksheet.cell(row=row, column=6, value=activity.ip_address or '')
                worksheet.cell(row=row, column=7, value=str(activity.content_type) if activity.content_type else '')
                worksheet.cell(row=row, column=8, value=activity.object_id or '')
                worksheet.cell(row=row, column=9, value=json.dumps(activity.old_values) if activity.old_values else '')
                worksheet.cell(row=row, column=10, value=json.dumps(activity.new_values) if activity.new_values else '')
            
            # Auto-adjust column widths
            for column in worksheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)  # Cap at 50 characters
                worksheet.column_dimensions[column_letter].width = adjusted_width
            
            workbook.save(response)
            
        else:  # CSV format
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="activity_history_{timezone.now().strftime("%Y%m%d_%H%M")}.csv"'
            
            writer = csv.writer(response)
            writer.writerow([
                'ID', 'User', 'Action', 'Description', 'Timestamp', 
                'IP Address', 'Content Type', 'Object ID', 'Old Values', 'New Values'
            ])
            
            for activity in activities:
                writer.writerow([
                    activity.id,
                    activity.user.username if activity.user else 'System',
                    activity.action,
                    activity.description,
                    activity.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    activity.ip_address or '',
                    str(activity.content_type) if activity.content_type else '',
                    activity.object_id or '',
                    json.dumps(activity.old_values) if activity.old_values else '',
                    json.dumps(activity.new_values) if activity.new_values else ''
                ])
        
        # Log the export activity
        try:
            AuditLog.objects.create(
                user=request.user,
                action='EXPORT',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f"Exported activity history as {format_type.upper()}",
                new_values={
                    'export_format': format_type,
                    'record_count': activities.count(),
                    'filters_applied': {
                        'action': action_filter,
                        'user': user_filter,
                        'date_from': date_from,
                        'date_to': date_to,
                        'search': search_query
                    }
                }
            )
        except:
            pass
        
        return response
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Export failed: {str(e)}'
        }, status=500)

@login_required
def bulk_history_operations(request):
    """Bulk operations on history records (for admins)"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=403)
    
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Invalid method'}, status=405)
    
    try:
        data = json.loads(request.body)
        action = data.get('action')
        activity_ids = data.get('activity_ids', [])
        
        if not activity_ids:
            return JsonResponse({'success': False, 'error': 'No activities selected'})
        
        activities = AuditLog.objects.filter(id__in=activity_ids)
        count = activities.count()
        
        if action == 'delete':
            # Store info about deleted activities for logging
            deleted_info = list(activities.values('id', 'action', 'description', 'user__username'))
            activities.delete()
            
            # Log the bulk deletion
            AuditLog.objects.create(
                user=request.user,
                action='BULK_DELETE',
                ip_address=get_client_ip(request),
                description=f"Bulk deleted {count} activity records",
                old_values={'deleted_activities': deleted_info}
            )
            
            return JsonResponse({
                'success': True,
                'message': f'{count} activities deleted successfully'
            })
        
        elif action == 'archive':
            # Mark as archived (you could add an 'archived' field to AuditLog)
            # For now, just add a note to the description
            activities.update(description=F('description') + ' [ARCHIVED]')
            
            AuditLog.objects.create(
                user=request.user,
                action='BULK_ARCHIVE',
                ip_address=get_client_ip(request),
                description=f"Bulk archived {count} activity records",
                new_values={'archived_count': count, 'activity_ids': activity_ids}
            )
            
            return JsonResponse({
                'success': True,
                'message': f'{count} activities archived successfully'
            })
        
        else:
            return JsonResponse({'success': False, 'error': 'Invalid action'})
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Bulk operation failed: {str(e)}'
        }, status=500)
    
@login_required
def activity_stats(request):
    """Get activity statistics for the dashboard"""
    try:
        today = timezone.now().date()
        yesterday = today - timedelta(days=1)
        last_7_days = today - timedelta(days=7)
        last_30_days = today - timedelta(days=30)
        
        stats = {
            'total_activities': AuditLog.objects.count(),
            'today_activities': AuditLog.objects.filter(timestamp__date=today).count(),
            'yesterday_activities': AuditLog.objects.filter(timestamp__date=yesterday).count(),
            'week_activities': AuditLog.objects.filter(timestamp__date__gte=last_7_days).count(),
            'month_activities': AuditLog.objects.filter(timestamp__date__gte=last_30_days).count(),
            'unique_users': AuditLog.objects.exclude(user__isnull=True).values('user').distinct().count(),
            'action_types': AuditLog.objects.values('action').distinct().count(),
        }
        
        # Activity breakdown by action type
        action_breakdown = list(
            AuditLog.objects.values('action')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        # Daily activity trend for the last 7 days
        daily_trend = []
        for i in range(7):
            date = today - timedelta(days=i)
            count = AuditLog.objects.filter(timestamp__date=date).count()
            daily_trend.append({
                'date': date.strftime('%Y-%m-%d'),
                'count': count
            })
        
        # Most active users
        active_users = list(
            AuditLog.objects.exclude(user__isnull=True)
            .values('user__username')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        stats.update({
            'action_breakdown': action_breakdown,
            'daily_trend': daily_trend,
            'active_users': active_users
        })
        
        return JsonResponse({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)




def employees_profile(request):
    # Handle POST - Add new employee with validation
    if request.method == 'POST':
        try:
            with transaction.atomic():  # Ensure data consistency
                name = request.POST.get('name', '').strip()
                id_no = request.POST.get('id_no', '').strip()
                task = request.POST.get('task', '').strip()
                email = request.POST.get('email', '').strip()
                phone = request.POST.get('phone', '').strip()
                department = request.POST.get('department', '')
                position = request.POST.get('position', '').strip()
                hire_date = request.POST.get('hire_date')
                supervisor_id = request.POST.get('supervisor')
                
                # Validation
                if not all([name, id_no, task]):
                    return JsonResponse({
                        'success': False, 
                        'error': 'Name, ID number, and task are required'
                    }, status=400)
                
                # Check for duplicate ID
                if Employee.objects.filter(id_no=id_no).exists():
                    return JsonResponse({
                        'success': False, 
                        'error': 'Employee ID already exists'
                    }, status=400)
                
                # Create employee
                employee_data = {
                    'name': name,
                    'id_no': id_no,
                    'task': task,
                    'department': department if department else None,
                    'position': position,
                }
                
                if email:
                    employee_data['email'] = email
                if phone:
                    employee_data['phone'] = phone
                if hire_date:
                    employee_data['hire_date'] = hire_date
                if supervisor_id:
                    employee_data['supervisor_id'] = supervisor_id
                
                employee = Employee.objects.create(**employee_data)
                
                messages.success(request, f'Employee {name} added successfully!')
                
                # Clear cache
                cache.delete('employee_stats')
                
                return redirect('employees_profile')
                
        except Exception as e:
            return JsonResponse({
                'success': False, 
                'error': f'Error creating employee: {str(e)}'
            }, status=400)
    
    # Handle GET - Display employees with advanced filtering and pagination
    search_query = request.GET.get('search', '').strip()
    department_filter = request.GET.get('department', '')
    status_filter = request.GET.get('status', '')
    sort_by = request.GET.get('sort', 'name')
    
    # Base queryset with optimizations
    employees = Employee.objects.select_related('supervisor').prefetch_related('subordinates')
    
    # Apply filters
    if search_query:
        employees = employees.filter(
            Q(name__icontains=search_query) |
            Q(id_no__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(task__icontains=search_query) |
            Q(position__icontains=search_query)
        )
    
    if department_filter:
        employees = employees.filter(department=department_filter)
    
    if status_filter:
        employees = employees.filter(status=status_filter)
    
    # Sorting
    valid_sort_fields = ['name', '-name', 'id_no', '-id_no', 'created_at', '-created_at', 'department']
    if sort_by in valid_sort_fields:
        employees = employees.order_by(sort_by)
    
    # Pagination
    paginator = Paginator(employees, 10)  # Show 10 employees per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get statistics (cached for performance)
    stats = cache.get('employee_stats')
    if not stats:
        try:
            stats = Employee.get_statistics()
        except AttributeError:
            # If get_statistics method doesn't exist, create basic stats
            stats = {
                'total': Employee.objects.count(),
                'active': Employee.objects.filter(status='active').count() if hasattr(Employee, 'status') else 0,
                'departments': Employee.objects.values('department').distinct().count()
            }
        cache.set('employee_stats', stats, 300)  # Cache for 5 minutes
    
    # Get choices for dropdowns
    supervisors = Employee.objects.filter(status='active') if hasattr(Employee, 'status') else Employee.objects.all()
    
    # Get department and status choices if they exist
    department_choices = getattr(Employee, 'DEPARTMENT_CHOICES', [])
    status_choices = getattr(Employee, 'STATUS_CHOICES', [])
    
    context = {
        'page_obj': page_obj,
        'search_query': search_query,
        'department_filter': department_filter,
        'status_filter': status_filter,
        'sort_by': sort_by,
        'stats': stats,
        'supervisors': supervisors,
        'department_choices': department_choices,
        'status_choices': status_choices,
    }
    
    return render(request, 'employees_profile.html', context)


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
    """Render the public certification form"""
    return render(request, 'civil_service_certification.html')


def application_letter(request):
    return render(request, 'application_letter.html')


def monitoring_filess(request):
    return render(request, 'monitoring_files.html')


def certification_filess(request):
    return render(request, 'certification_filess.html')



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


@login_required
def export_employees(request):
    """Export employees data"""
    format_type = request.GET.get('format', 'csv')
    
    employees = Employee.objects.select_related('supervisor').all()
    
    if format_type == 'excel':
        # Create Excel file
        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="employees_{datetime.now().strftime("%Y%m%d")}.xlsx"'
        
        workbook = openpyxl.Workbook()
        worksheet = workbook.active
        worksheet.title = 'Employees'
        
        # Headers
        headers = ['ID', 'Name', 'Employee ID', 'Email', 'Department', 'Position', 'Status', 'Task', 'Supervisor', 'Hire Date', 'Created At']
        for col, header in enumerate(headers, 1):
            worksheet.cell(row=1, column=col, value=header)
        
        # Data
        for row, employee in enumerate(employees, 2):
            worksheet.cell(row=row, column=1, value=employee.id)
            worksheet.cell(row=row, column=2, value=employee.name)
            worksheet.cell(row=row, column=3, value=employee.id_no)
            worksheet.cell(row=row, column=4, value=getattr(employee, 'email', '') or '')
            
            # Handle department display
            if hasattr(employee, 'get_department_display'):
                dept = employee.get_department_display() or ''
            else:
                dept = getattr(employee, 'department', '') or ''
            worksheet.cell(row=row, column=5, value=dept)
            
            worksheet.cell(row=row, column=6, value=getattr(employee, 'position', '') or '')
            
            # Handle status display
            if hasattr(employee, 'get_status_display'):
                status = employee.get_status_display()
            else:
                status = getattr(employee, 'status', '') or ''
            worksheet.cell(row=row, column=7, value=status)
            
            worksheet.cell(row=row, column=8, value=getattr(employee, 'task', '') or '')
            worksheet.cell(row=row, column=9, value=employee.supervisor.name if employee.supervisor else '')
            worksheet.cell(row=row, column=10, value=getattr(employee, 'hire_date', ''))
            worksheet.cell(row=row, column=11, value=getattr(employee, 'created_at', ''))
        
        workbook.save(response)
        
    else:  # CSV format
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="employees_{datetime.now().strftime("%Y%m%d")}.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['ID', 'Name', 'Employee ID', 'Email', 'Department', 'Position', 'Status', 'Task', 'Supervisor', 'Hire Date', 'Created At'])
        
        for employee in employees:
            # Handle department display
            if hasattr(employee, 'get_department_display'):
                dept = employee.get_department_display() or ''
            else:
                dept = getattr(employee, 'department', '') or ''
            
            # Handle status display
            if hasattr(employee, 'get_status_display'):
                status = employee.get_status_display()
            else:
                status = getattr(employee, 'status', '') or ''
            
            writer.writerow([
                employee.id,
                employee.name,
                employee.id_no,
                getattr(employee, 'email', '') or '',
                dept,
                getattr(employee, 'position', '') or '',
                status,
                getattr(employee, 'task', '') or '',
                employee.supervisor.name if employee.supervisor else '',
                getattr(employee, 'hire_date', ''),
                getattr(employee, 'created_at', '')
            ])
    
    # Log export action
    try:
        AuditLog.objects.create(
            user=request.user,
            action='CREATE',
            description=f"Exported employees data as {format_type.upper()}"
        )
    except:
        pass  # Skip audit logging if AuditLog doesn't exist
    
    return response


@login_required
@role_required('dilg staff')
def analytics_dashboard(request):
    """Advanced analytics dashboard"""
    
    # Time-based statistics
    today = timezone.now().date()
    last_30_days = today - timedelta(days=30)
    last_7_days = today - timedelta(days=7)
    
    # Employee metrics
    total_employees = Employee.objects.count()
    print(f"DEBUG: Total employees found: {total_employees}")
    
    # Fix for new employees - check if created_at field exists and has data
    if hasattr(Employee, 'created_at'):
        new_employees_30d = Employee.objects.filter(created_at__date__gte=last_30_days).count()
    else:
        new_employees_30d = 0
    
    # Fix for active employees - count all OR only active status
    if hasattr(Employee, 'status'):
        # Count employees with active status OR null/empty status (treat as active)
        active_employees = Employee.objects.filter(
            Q(status='active') | Q(status__isnull=True) | Q(status='')
        ).count()
        print(f"DEBUG: Active employees: {active_employees}")
        
        # If still 0, just count all employees as active
        if active_employees == 0:
            active_employees = total_employees
    else:
        active_employees = total_employees
    
    # Department statistics - with better error handling
    dept_stats = []
    try:
        dept_stats = list(Employee.objects.values('department')
                         .annotate(count=Count('id'))
                         .order_by('-count'))
        print(f"DEBUG: Department stats: {dept_stats}")
        
        # Clean up None departments
        for stat in dept_stats:
            if not stat['department']:
                stat['department'] = 'Unassigned'
                
    except Exception as e:
        print(f"DEBUG: Error getting dept stats: {e}")
        pass
    
    # Task distribution - with better error handling
    task_stats = []
    try:
        task_stats = list(Employee.objects.exclude(task__isnull=True)
                         .exclude(task='')
                         .values('task')
                         .annotate(count=Count('id'))
                         .order_by('-count')[:10])
        print(f"DEBUG: Task stats: {task_stats}")
    except Exception as e:
        print(f"DEBUG: Error getting task stats: {e}")
        pass
    
    # Recent activities from audit log
    recent_activities = []
    user_activity = []
    try:
        recent_activities = AuditLog.objects.select_related('user')\
                                          .filter(timestamp__date__gte=last_7_days)\
                                          .order_by('-timestamp')[:20]
        
        # User activity stats
        user_activity = AuditLog.objects.filter(action='LOGIN', timestamp__date__gte=last_30_days)\
                                       .values('user__username')\
                                       .annotate(login_count=Count('id'))\
                                       .order_by('-login_count')[:10]
    except Exception as e:
        print(f"DEBUG: Error getting audit logs: {e}")
        pass
    
    # System health metrics
    db_size = 0
    table_stats = []
    try:
        with connection.cursor() as cursor:
            # Database size (SQLite specific)
            cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size();")
            result = cursor.fetchone()
            if result:
                db_size = result[0]
            
            # Basic table stats
            table_stats = [
                ('Employees', Employee.objects.count()),
                ('Users', User.objects.count()),
            ]
    except Exception as e:
        print(f"DEBUG: Error getting system stats: {e}")
        pass
    
    context = {
        'total_employees': total_employees,
        'new_employees_30d': new_employees_30d,
        'active_employees': active_employees,
        'dept_stats': dept_stats,
        'task_stats': task_stats,
        'recent_activities': recent_activities,
        'user_activity': user_activity,
        'db_size': db_size,
        'table_stats': table_stats,
    }
    
    print(f"DEBUG: Final context: {context}")
    return render(request, 'analytics_dashboard.html', context)


# Advanced search API
@login_required
def employee_search_api(request):
    """AJAX endpoint for advanced employee search"""
    query = request.GET.get('q', '').strip()
    
    if len(query) < 2:
        return JsonResponse({'employees': []})
    
    # Complex search across multiple fields
    try:
        employees = Employee.objects.filter(
            Q(name__icontains=query) |
            Q(id_no__icontains=query) |
            Q(email__icontains=query) |
            Q(position__icontains=query) |
            Q(department__icontains=query)
        ).values('id', 'name', 'id_no', 'email', 'department', 'status')[:10]
    except:
        employees = Employee.objects.filter(
            Q(name__icontains=query) |
            Q(id_no__icontains=query)
        ).values('id', 'name', 'id_no')[:10]
    
    return JsonResponse({
        'employees': list(employees)
    })


# Bulk operations
@login_required
@require_http_methods(["POST"])
def bulk_employee_operations(request):
    """Handle bulk operations on employees"""
    try:
        data = json.loads(request.body)
        action = data.get('action')
        employee_ids = data.get('employee_ids', [])
        
        if not employee_ids:
            return JsonResponse({'success': False, 'error': 'No employees selected'})
        
        with transaction.atomic():
            employees = Employee.objects.filter(id__in=employee_ids)
            
            if action == 'delete':
                count = employees.count()
                employees.delete()
                message = f'{count} employees deleted successfully'
                
            elif action == 'activate':
                if hasattr(Employee, 'status'):
                    count = employees.update(status='active')
                    message = f'{count} employees activated'
                else:
                    return JsonResponse({'success': False, 'error': 'Status field not available'})
                
            elif action == 'deactivate':
                if hasattr(Employee, 'status'):
                    count = employees.update(status='inactive')
                    message = f'{count} employees deactivated'
                else:
                    return JsonResponse({'success': False, 'error': 'Status field not available'})
                
            elif action == 'update_department':
                department = data.get('department')
                if not department:
                    return JsonResponse({'success': False, 'error': 'Department required'})
                if hasattr(Employee, 'department'):
                    count = employees.update(department=department)
                    message = f'{count} employees moved to {department}'
                else:
                    return JsonResponse({'success': False, 'error': 'Department field not available'})
                
            else:
                return JsonResponse({'success': False, 'error': 'Invalid action'})
            
            # Log bulk operation
            try:
                AuditLog.objects.create(
                    user=request.user,
                    action='UPDATE',
                    description=f"Bulk operation: {action} on {len(employee_ids)} employees"
                )
            except:
                pass  # Skip audit logging if AuditLog doesn't exist
            
            # Clear cache
            cache.delete('employee_stats')
            
            return JsonResponse({'success': True, 'message': message})
            
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})
    

@require_http_methods(["POST"])
def submit_eligibility_request(request):
    """Handle form submission from the public certification form"""
    try:
        # Debug logging
        print("=== FORM SUBMISSION DEBUG ===")
        print("POST data:", dict(request.POST))
        print("FILES data:", dict(request.FILES))
        print("Content-Type:", request.content_type)
        
        # Extract and validate form data
        last_name = request.POST.get('last_name', '').strip()
        first_name = request.POST.get('first_name', '').strip()
        middle_initial = request.POST.get('middle_initial', '').strip()
        email = request.POST.get('email', '').strip()  # ← ADD THIS LINE
        certifier = request.POST.get('certifier', '').strip()
        
        # Validation
        if not last_name:
            return JsonResponse({
                'success': False,
                'error': 'Last name is required'
            }, status=400)
            
        if not first_name:
            return JsonResponse({
                'success': False,
                'error': 'First name is required'
            }, status=400)
        
        # ← ADD THIS EMAIL VALIDATION
        if not email:
            return JsonResponse({
                'success': False,
                'error': 'Email address is required'
            }, status=400)
            
        if not certifier:
            return JsonResponse({
                'success': False,
                'error': 'Certifier selection is required'
            }, status=400)
        
        # Validate certifier choice against model choices
        valid_certifiers = [choice[0] for choice in EligibilityRequest.CERTIFIER_CHOICES]
        if certifier not in valid_certifiers:
            return JsonResponse({
                'success': False,
                'error': f'Invalid certifier selection. Must be one of: {valid_certifiers}'
            }, status=400)
        
        # Handle file uploads
        id_front = request.FILES.get('id_front')
        id_back = request.FILES.get('id_back')
        signature = request.FILES.get('signature')
        
        print(f"Files found - id_front: {id_front is not None}, id_back: {id_back is not None}, signature: {signature is not None}")
        
        if not id_front:
            return JsonResponse({
                'success': False,
                'error': 'Front ID image is required'
            }, status=400)
            
        if not id_back:
            return JsonResponse({
                'success': False,
                'error': 'Back ID image is required'
            }, status=400)
            
        if not signature:
            return JsonResponse({
                'success': False,
                'error': 'Signature is required'
            }, status=400)
        
        # Create new request using the correct field names from your model
        try:
            eligibility_request = EligibilityRequest.objects.create(
                first_name=first_name,
                last_name=last_name,
                middle_initial=middle_initial if middle_initial else None,
                email=email,  # ← ADD THIS LINE
                certifier=certifier,
                id_front=id_front,
                id_back=id_back,
                signature=signature,
                status='pending',
                date_submitted=timezone.now()
            )
            
            print(f"Successfully created request with ID: {eligibility_request.id}")
            
            # Generate a reference number for the user
            reference_number = f"EC-{timezone.now().year}-{eligibility_request.id:03d}"
            
            return JsonResponse({
                'success': True,
                'message': 'Application submitted successfully! Check your email for confirmation.',  # ← UPDATED MESSAGE
                'id_number': reference_number,  
                'request_id': eligibility_request.id
            })
            
        except Exception as create_error:
            print(f"Error creating EligibilityRequest: {create_error}")
            print(f"Error type: {type(create_error).__name__}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            
            return JsonResponse({
                'success': False,
                'error': f'Database error: {str(create_error)}'
            }, status=400)
        
    except Exception as e:
        print(f"=== SUBMISSION ERROR ===")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        
        return JsonResponse({
            'success': False,
            'error': f'Submission failed: {str(e)}'
        }, status=400)

@login_required
def application_request(request):
    """Render the admin application request management page"""
    # Get all eligibility requests
    requests = EligibilityRequest.objects.all().order_by('-date_submitted')
    
    context = {
        'requests': requests
    }
    return render(request, 'application_request.html', context)

@login_required
@require_http_methods(["POST"])
def update_application_status(request):
    """Update the status of an eligibility request"""
    try:
        # Parse JSON data
        data = json.loads(request.body)
        request_id = data.get('id')
        new_status = data.get('status')
        
        # Validate input
        if not request_id:
            return JsonResponse({
                'success': False,
                'error': 'Request ID is required'
            }, status=400)
            
        if not new_status:
            return JsonResponse({
                'success': False,
                'error': 'Status is required'
            }, status=400)
        
        # Validate status choice
        valid_statuses = ['pending', 'approved', 'rejected', 'processing']
        if new_status not in valid_statuses:
            return JsonResponse({
                'success': False,
                'error': f'Invalid status. Must be one of: {valid_statuses}'
            }, status=400)
        
        # Get the request
        try:
            eligibility_request = EligibilityRequest.objects.get(id=request_id)
        except EligibilityRequest.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Request not found'
            }, status=404)
        
        # Update status
        eligibility_request.status = new_status
        
        # Update approved_by and date_processed for approved/rejected status
        if new_status in ['approved', 'rejected']:
            eligibility_request.approved_by = request.user
            eligibility_request.date_processed = timezone.now()  # Use timezone.now()
        elif new_status == 'pending':
            # Reset approval fields when changing back to pending
            eligibility_request.approved_by = None
            eligibility_request.date_processed = None
        
        eligibility_request.save()
        
        # Prepare response data
        approved_by_name = None
        if eligibility_request.approved_by:
            approved_by_name = eligibility_request.approved_by.get_full_name() or eligibility_request.approved_by.username
        else:
            approved_by_name = '-'
        
        return JsonResponse({
            'success': True,
            'message': f'Status updated to {new_status.capitalize()}',
            'approved_by': approved_by_name,
            'new_status': new_status
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        # Log the actual error for debugging
        import traceback
        print(f"Error updating application status: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        
        return JsonResponse({
            'success': False,
            'error': f'Server error: {str(e)}'
        }, status=500)
    


#-----------------REQUIREMENTS_MONITORING--------------
@require_http_methods(["GET"])
def user_profile(request):
    return JsonResponse({
        'success': True,
        'user': {
            'full_name': request.user.get_full_name(),
            'email': request.user.email,
            'username': request.user.username,
            'role': request.user.groups.first().name if request.user.groups.exists() else 'User',
            'barangay': request.user.profile.barangay.name if hasattr(request.user, 'profile') else 'Not assigned',
            'member_since': request.user.date_joined.strftime('%B %d, %Y')
        }
    })
@login_required
def requirements_monitoring(request):
    """
    Main requirements monitoring page with color-coded barangay status
    """
    user_profile = request.user.userprofile
    
    if user_profile.role == 'dilg staff':
        messages.info(request, 'As DILG Admin, please use the Admin Submissions page.')
        return redirect('admin_submissions')
    
    # Get all barangays
    barangays = Barangay.objects.all()
    
    # Calculate status for each barangay
    barangay_statuses = {}
    today = date.today()
    
    for barangay in barangays:
        # Get all submissions for this barangay
        submissions = RequirementSubmission.objects.filter(barangay=barangay)
        
        if not submissions.exists():
            # No requirements yet
            barangay_statuses[barangay.id] = {
                'status': 'no_data',
                'color': 'gray',
                'tooltip': 'No requirements assigned'
            }
            continue
        
        # Count different statuses
        total = submissions.count()
        overdue = submissions.filter(
            Q(status__in=['pending', 'in_progress']) & Q(due_date__lt=today)
        ).count()
        pending = submissions.filter(status='pending').count()
        in_progress = submissions.filter(status='in_progress').count()
        accomplished = submissions.filter(status='accomplished').count()
        
        # Determine color based on priority
        if overdue > 0:
            status = 'overdue'
            color = 'red'
            tooltip = f'{overdue} overdue requirement(s)'
        elif pending > 0 or in_progress > 0:
            status = 'in_progress'
            color = 'yellow'
            tooltip = f'{pending} pending, {in_progress} in progress'
        elif accomplished == total:
            status = 'completed'
            color = 'green'
            tooltip = f'All {total} requirements completed!'
        else:
            status = 'partial'
            color = 'blue'
            tooltip = f'{accomplished}/{total} completed'
        
        barangay_statuses[barangay.id] = {
            'status': status,
            'color': color,
            'tooltip': tooltip,
            'counts': {
                'total': total,
                'overdue': overdue,
                'pending': pending,
                'in_progress': in_progress,
                'accomplished': accomplished
            }
        }
    
    context = {
        'barangays': barangays,
        'barangay_statuses': barangay_statuses,
        'user_role': user_profile.role,
        'is_submitter': user_profile.role == 'barangay official',
    }
    return render(request, 'requirements_monitoring.html', context)


import logging
logger = logging.getLogger(__name__)
@login_required
def get_barangay_status(request, barangay_id):
    """
    API endpoint to get real-time barangay status
    
    Color Logic (FIXED):
    - RED: Has overdue requirements (past due date and NOT approved/rejected)
    - GREEN: All requirements completed AND approved
    - YELLOW: Has in-progress requirements
    - BLUE: Has pending requirements
    - GRAY: No requirements assigned
    """
    try:
        barangay = Barangay.objects.get(id=barangay_id)
        submissions = RequirementSubmission.objects.filter(barangay=barangay)
        today = date.today()
        
        if not submissions.exists():
            return JsonResponse({
                'status': 'no_data',
                'color': 'gray',
                'tooltip': f'{barangay.name}: No requirements assigned',
                'counts': {
                    'total': 0,
                    'overdue': 0,
                    'pending': 0,
                    'in_progress': 0,
                    'accomplished': 0,
                    'approved': 0,
                    'rejected': 0
                }
            })
        
        total = submissions.count()
        
        # FIXED: Overdue only counts items NOT approved/rejected
        overdue = submissions.filter(
            status__in=['pending', 'in_progress', 'accomplished'],
            due_date__lt=today
        ).count()
        
        pending = submissions.filter(status='pending').count()
        in_progress = submissions.filter(status='in_progress').count()
        accomplished = submissions.filter(status='accomplished').count()
        approved = submissions.filter(status='approved').count()
        rejected = submissions.filter(status='rejected').count()
        
        # Priority 1: If ANY requirements are overdue (and not approved/rejected) -> RED
        if overdue > 0:
            return JsonResponse({
                'status': 'overdue',
                'color': 'red',
                'tooltip': f'{barangay.name}: {overdue} overdue requirement(s) ⚠️',
                'counts': {
                    'total': total,
                    'overdue': overdue,
                    'pending': pending,
                    'in_progress': in_progress,
                    'accomplished': accomplished,
                    'approved': approved,
                    'rejected': rejected
                }
            })
        
        # Priority 2: If ALL requirements are approved -> GREEN
        elif approved == total:
            return JsonResponse({
                'status': 'completed',
                'color': 'green',
                'tooltip': f'{barangay.name}: All {total} requirements approved! ✓',
                'counts': {
                    'total': total,
                    'overdue': 0,
                    'pending': 0,
                    'in_progress': 0,
                    'accomplished': 0,
                    'approved': approved,
                    'rejected': rejected
                }
            })
        
        # Priority 3: If has in-progress or accomplished (waiting review) -> YELLOW
        elif in_progress > 0 or accomplished > 0:
            return JsonResponse({
                'status': 'in_progress',
                'color': 'yellow',
                'tooltip': f'{barangay.name}: {in_progress} in progress, {accomplished} awaiting review',
                'counts': {
                    'total': total,
                    'overdue': 0,
                    'pending': pending,
                    'in_progress': in_progress,
                    'accomplished': accomplished,
                    'approved': approved,
                    'rejected': rejected
                }
            })
        
        # Priority 4: If only pending -> BLUE
        elif pending > 0:
            return JsonResponse({
                'status': 'pending',
                'color': 'blue',
                'tooltip': f'{barangay.name}: {pending} pending requirements',
                'counts': {
                    'total': total,
                    'overdue': 0,
                    'pending': pending,
                    'in_progress': 0,
                    'accomplished': 0,
                    'approved': approved,
                    'rejected': rejected
                }
            })
        
        # Partially complete (some approved, some not)
        else:
            return JsonResponse({
                'status': 'partial',
                'color': 'blue',
                'tooltip': f'{barangay.name}: {approved}/{total} approved',
                'counts': {
                    'total': total,
                    'overdue': 0,
                    'pending': pending,
                    'in_progress': in_progress,
                    'accomplished': accomplished,
                    'approved': approved,
                    'rejected': rejected
                }
            })
            
    except Barangay.DoesNotExist:
        return JsonResponse({
            'error': 'Barangay not found',
            'status': 'error',
            'color': 'gray'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'error': str(e),
            'status': 'error',
            'color': 'gray'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def api_requirements_list(request):
    """API endpoint to list requirements for a barangay"""
    try:
        barangay_id = request.GET.get('barangay_id')
        period = request.GET.get('period', 'weekly')
        week = request.GET.get('week', 1)
        search = request.GET.get('search', '').strip()
        
        if not barangay_id:
            return JsonResponse({'success': False, 'error': 'Barangay ID required'}, status=400)
        
        barangay = get_object_or_404(Barangay, id=barangay_id)
        
        # Get submissions for this barangay and period
        submissions = RequirementSubmission.objects.filter(
            barangay=barangay,
            requirement__period=period,
            requirement__is_active=True
        )
        
        # Filter by week if period is weekly
        if period == 'weekly':
            submissions = submissions.filter(week_number=week)
        
        # Search filter
        if search:
            submissions = submissions.filter(
                Q(requirement__title__icontains=search) |
                Q(requirement__description__icontains=search)
            )
        
        # Prepare response data
        submissions_data = []
        for sub in submissions:
            submissions_data.append({
                'id': sub.id,
                'title': sub.requirement.title,
                'description': sub.requirement.description,
                'status': sub.status,
                'status_display': sub.get_status_display(),
                'due_date': sub.due_date.strftime('%B %d, %Y'),
                'is_overdue': sub.is_overdue,
                'last_update': sub.updated_at.strftime('%B %d, %Y at %I:%M %p'),
                'update_text': sub.update_text,
            })
        
        return JsonResponse({
            'success': True,
            'submissions': submissions_data
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@require_http_methods(["GET"])
def api_submission_detail(request, submission_id):
    """API endpoint to get submission details"""
    try:
        # Use select_related and prefetch_related for efficiency
        submission = get_object_or_404(
            RequirementSubmission.objects.select_related(
                'requirement', 'barangay', 'submitted_by'
            ).prefetch_related('attachments'),
            id=submission_id
        )
        
        # Get attachments safely
        attachments = []
        for att in submission.attachments.all():
            try:
                file_name = os.path.basename(att.file.name) if att.file else 'Unknown'
                file_url = att.file.url if att.file else ''
                file_size = att.file_size_kb if hasattr(att, 'file_size_kb') else round(att.file_size / 1024, 2)
                
                attachments.append({
                    'id': att.id,
                    'file_name': file_name,
                    'file_size': file_size,
                    'file_url': file_url,
                    'uploaded_at': att.uploaded_at.strftime('%B %d, %Y at %I:%M %p'),
                })
            except Exception as att_error:
                print(f"Error processing attachment {att.id}: {att_error}")
                continue
        
        data = {
            'id': submission.id,
            'requirement': {
                'title': submission.requirement.title,
                'description': submission.requirement.description,
                'period': submission.requirement.period,
            },
            'barangay': {
                'id': submission.barangay.id,
                'name': submission.barangay.name,
            },
            'status': submission.status,
            'status_display': submission.get_status_display(),
            'due_date': submission.due_date.strftime('%B %d, %Y'),
            'is_overdue': submission.is_overdue,
            'update_text': submission.update_text or '',
            'last_update': submission.updated_at.strftime('%B %d, %Y at %I:%M %p'),
            'attachments': attachments,
        }
        
        return JsonResponse({
            'success': True,
            'submission': data
        })
        
    except RequirementSubmission.DoesNotExist:
        return JsonResponse({
            'success': False, 
            'error': f'Submission with ID {submission_id} not found'
        }, status=404)
    except Exception as e:
        # Log the full error for debugging
        import traceback
        print(f"=== ERROR in api_submission_detail ===")
        print(f"Submission ID: {submission_id}")
        print(f"Error: {str(e)}")
        print(f"Traceback:\n{traceback.format_exc()}")
        
        return JsonResponse({
            'success': False, 
            'error': f'Internal server error: {str(e)}'
        }, status=500)


@login_required
def debug_submission(request, submission_id):
    try:
        sub = RequirementSubmission.objects.get(id=submission_id)
        return JsonResponse({
            'submission_exists': True,
            'requirement_title': sub.requirement.title,
            'barangay_name': sub.barangay.name,
            'attachment_count': sub.attachments.count(),
            'status': sub.status
        })
    except Exception as e:
        return JsonResponse({'error': str(e)})

@login_required
@require_http_methods(["POST"])
def api_submission_update(request, submission_id):
    """API endpoint to update submission text"""
    try:
        submission = get_object_or_404(RequirementSubmission, id=submission_id)
        
        update_text = request.POST.get('update_text', '').strip()
        
        if not update_text:
            return JsonResponse({'success': False, 'error': 'Update text required'}, status=400)
        
        submission.update_text = update_text
        submission.save()
        
        # Log the update
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_object=submission,
            description=f"Updated requirement: {submission.requirement.title}"
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Update saved successfully',
            'submission': {
                'id': submission.id,
                'update_text': submission.update_text,
                'last_update': submission.updated_at.strftime('%B %d, %Y at %I:%M %p'),
            }
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def api_attachment_upload(request):
    """API endpoint to upload file attachments"""
    try:
        # Debug logging
        print("=== FILE UPLOAD DEBUG ===")
        print(f"POST data: {request.POST}")
        print(f"FILES data: {request.FILES}")
        print(f"User: {request.user}")
        
        submission_id = request.POST.get('submission_id')
        
        if not submission_id:
            print("ERROR: No submission_id provided")
            return JsonResponse({
                'success': False, 
                'error': 'Submission ID required'
            }, status=400)
        
        print(f"Looking for submission ID: {submission_id}")
        
        try:
            submission = RequirementSubmission.objects.get(id=submission_id)
            print(f"Found submission: {submission}")
        except RequirementSubmission.DoesNotExist:
            print(f"ERROR: Submission {submission_id} not found")
            return JsonResponse({
                'success': False, 
                'error': f'Submission with ID {submission_id} not found'
            }, status=404)
        
        if 'file' not in request.FILES:
            print("ERROR: No file in request.FILES")
            return JsonResponse({
                'success': False, 
                'error': 'No file uploaded'
            }, status=400)
        
        file = request.FILES['file']
        print(f"File received: {file.name}, size: {file.size}, type: {file.content_type}")
        
        # Validate file type
        if not file.content_type.startswith('image/'):
            print(f"ERROR: Invalid file type: {file.content_type}")
            return JsonResponse({
                'success': False, 
                'error': 'Only image files allowed'
            }, status=400)
        
        # Validate file size (5MB limit)
        if file.size > 5 * 1024 * 1024:
            print(f"ERROR: File too large: {file.size} bytes")
            return JsonResponse({
                'success': False, 
                'error': 'File size must be less than 5MB'
            }, status=400)
        
        # Create attachment
        print("Creating attachment...")
        attachment = RequirementAttachment.objects.create(
            submission=submission,
            file=file,
            file_type=file.content_type,
            file_size=file.size,
            uploaded_by=request.user
        )
        print(f"Attachment created with ID: {attachment.id}")
        
        # Log the upload
        try:
            AuditLog.objects.create(
                user=request.user,
                action='CREATE',
                content_object=attachment,
                description=f"Uploaded attachment for: {submission.requirement.title}"
            )
        except Exception as log_error:
            print(f"Warning: Failed to create audit log: {log_error}")
        
        response_data = {
            'success': True,
            'message': 'File uploaded successfully',
            'attachment': {
                'id': attachment.id,
                'file_name': os.path.basename(attachment.file.name),
                'file_size': attachment.file_size_kb,
                'file_url': attachment.file.url,
                'uploaded_at': attachment.uploaded_at.strftime('%B %d, %Y at %I:%M %p'),
            }
        }
        
        print(f"SUCCESS: Returning response: {response_data}")
        return JsonResponse(response_data)
        
    except Exception as e:
        print(f"=== UPLOAD ERROR ===")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        import traceback
        print(f"Traceback:\n{traceback.format_exc()}")
        
        return JsonResponse({
            'success': False, 
            'error': f'Upload failed: {str(e)}'
        }, status=500)

@login_required
@require_http_methods(["POST"])
def api_attachment_delete(request, attachment_id):
    """API endpoint to delete attachment"""
    try:
        attachment = get_object_or_404(RequirementAttachment, id=attachment_id)
        
        # Check if user has permission to delete
        if attachment.uploaded_by != request.user and not request.user.is_staff:
            return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)
        
        # Log before deletion
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            description=f"Deleted attachment: {os.path.basename(attachment.file.name)}"
        )
        
        attachment.delete()
        
        return JsonResponse({
            'success': True,
            'message': 'File removed successfully'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def api_submission_submit(request, submission_id):
    """
    API endpoint to submit requirement to admin
    When barangay official submits, DILG admin automatically sees it
    """
    try:
        # 🔒 Access Control - Only Barangay Officials can submit
        user_profile = request.user.userprofile
        if user_profile.role not in ['barangay official', 'municipal officer']:
            return JsonResponse({
                'success': False,
                'error': 'Only Barangay Officials can submit requirements'
            }, status=403)
        
        submission = get_object_or_404(RequirementSubmission, id=submission_id)
        
        # Get update_text from POST
        update_text = request.POST.get('update_text', '').strip()
        
        if update_text:
            submission.update_text = update_text
            submission.save()
        
        # Validate required fields
        if not submission.update_text:
            return JsonResponse({
                'success': False, 
                'error': 'Please add update details before submitting'
            }, status=400)
        
        if not submission.attachments.exists():
            return JsonResponse({
                'success': False,
                'error': 'Please upload at least one image before submitting'
            }, status=400)
        
        # ✅ SUBMIT TO ADMIN - Change status to 'accomplished'
        # This makes it visible to DILG admin immediately
        submission.status = 'accomplished'
        submission.submitted_by = request.user
        submission.submitted_at = timezone.now()
        submission.save()
        
        # 📧 Optional: Send email notification to DILG admin
        # (You can add this if needed)
        try:
            from django.core.mail import send_mail
            send_mail(
                subject=f'New Requirement Submitted: {submission.requirement.title}',
                message=f'{submission.barangay.name} submitted: {submission.requirement.title}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[settings.EMAIL_HOST_USER],  # DILG admin email
                fail_silently=True,
            )
        except:
            pass  # Don't fail submission if email fails
        
        # Log the submission
        try:
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                content_object=submission,
                description=f"Submitted requirement to DILG Admin: {submission.requirement.title} from {submission.barangay.name}"
            )
        except:
            pass
        
        return JsonResponse({
            'success': True,
            'message': '✅ Successfully submitted to DILG Admin!',
            'submission': {
                'id': submission.id,
                'status': submission.status,
                'status_display': submission.get_status_display(),
                'submitted_at': submission.submitted_at.strftime('%B %d, %Y at %I:%M %p')
            }
        })
        
    except Exception as e:
        import traceback
        print(f"=== SUBMIT ERROR ===")
        print(f"Error: {str(e)}")
        print(f"Traceback:\n{traceback.format_exc()}")
        
        return JsonResponse({
            'success': False, 
            'error': str(e)
        }, status=500)



@login_required
@require_http_methods(["POST"])
def api_submission_delete(request, submission_id):
    """API endpoint to delete submission"""
    try:
        submission = get_object_or_404(RequirementSubmission, id=submission_id)
        
        # Check if user has permission
        if not request.user.is_staff:
            return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)
        
        # Log before deletion
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            description=f"Deleted submission: {submission.requirement.title} - {submission.barangay.name}"
        )
        
        submission.delete()
        
        return JsonResponse({
            'success': True,
            'message': 'Requirement deleted successfully'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def requirements_monitoring(request):
    """
    Requirements submission page - BARANGAY OFFICIALS ONLY
    This is where barangay officials submit their requirements
    """
    user_profile = request.user.userprofile
    
    # 🔒 STRICT ACCESS CONTROL - Only Barangay Officials
    if user_profile.role == 'dilg staff':
        messages.warning(request, '⚠️ DILG Admin should use the Admin Submissions page to review submissions.')
        return redirect('admin_submissions_page')  # Redirect to admin page
    
    if user_profile.role not in ['barangay official', 'municipal officer']:
        messages.error(request, '🚫 Access Denied: This page is only for Barangay Officials.')
        return redirect('dashboard')
    
    # Get barangays for barangay officials
    barangays = Barangay.objects.all().order_by('id') 
    
    context = {
        'barangays': barangays,
        'user_role': user_profile.role,
        'page_title': 'Submit Requirements',
        'is_submitter': True,  # Flag to show this is submission page
    }
    return render(request, 'requirements_monitoring.html', context)


@login_required
@require_http_methods(["GET"])
def get_requirements_list(request):
    """AJAX endpoint to get requirements list for a barangay"""
    try:
        barangay_id = request.GET.get('barangay_id')
        period = request.GET.get('period', 'weekly')
        week = request.GET.get('week', 1)
        search = request.GET.get('search', '')
        
        if not barangay_id:
            return JsonResponse({
                'success': False,
                'error': 'Barangay ID is required'
            }, status=400)
        
        barangay = get_object_or_404(Barangay, id=barangay_id)
        
        # Get current year and week
        current_year = timezone.now().year
        current_week = int(week)
        
        # Get requirements for this period
        requirements = Requirement.objects.filter(
            Q(period=period) & Q(is_active=True)
        ).filter(
            Q(applicable_barangays=barangay) | Q(applicable_barangays__isnull=True)
        )
        
        # Apply search filter
        if search:
            requirements = requirements.filter(
                Q(title__icontains=search) | Q(description__icontains=search)
            )
        
        # Get or create submissions for these requirements
        submissions_data = []
        for req in requirements:
            # Get or create submission for this week/period
            submission, created = RequirementSubmission.objects.get_or_create(
                requirement=req,
                barangay=barangay,
                week_number=current_week if period == 'weekly' else None,
                year=current_year,
                defaults={
                    'due_date': calculate_due_date(period, current_week, current_year),
                    'status': 'pending'
                }
            )
            
            submissions_data.append({
                'id': submission.id,
                'requirement_id': req.id,
                'title': req.title,
                'description': req.description,
                'status': submission.status,
                'status_display': submission.get_status_display(),
                'due_date': submission.due_date.strftime('%B %d, %Y'),
                'last_update': submission.updated_at.strftime('%B %d, %Y'),
                'is_overdue': submission.is_overdue,
                'has_attachments': submission.attachments.exists(),
                'attachment_count': submission.attachments.count(),
            })
        
        return JsonResponse({
            'success': True,
            'submissions': submissions_data,
            'barangay_name': barangay.name,
            'period': period,
            'week': current_week
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_http_methods(["GET"])
def get_submission_detail(request, submission_id):
    """Get detailed information about a specific submission"""
    try:
        submission = get_object_or_404(
            RequirementSubmission.objects.select_related(
                'requirement', 'barangay', 'submitted_by', 'reviewed_by'
            ).prefetch_related('attachments'),
            id=submission_id
        )
        
        # Get attachments
        attachments = []
        for attachment in submission.attachments.all():
            attachments.append({
                'id': attachment.id,
                'file_url': attachment.file.url,
                'file_name': attachment.file.name.split('/')[-1],
                'file_size': attachment.file_size_kb,
                'file_type': attachment.file_type,
                'uploaded_at': attachment.uploaded_at.strftime('%B %d, %Y %I:%M %p')
            })
        
        data = {
            'id': submission.id,
            'requirement': {
                'title': submission.requirement.title,
                'description': submission.requirement.description,
                'period': submission.requirement.get_period_display()
            },
            'barangay': {
                'name': submission.barangay.name,
                'code': submission.barangay.code
            },
            'status': submission.status,
            'status_display': submission.get_status_display(),
            'due_date': submission.due_date.strftime('%B %d, %Y'),
            'week_number': submission.week_number,
            'year': submission.year,
            'update_text': submission.update_text or '',
            'is_overdue': submission.is_overdue,
            'submitted_by': submission.submitted_by.get_full_name() if submission.submitted_by else None,
            'submitted_at': submission.submitted_at.strftime('%B %d, %Y %I:%M %p') if submission.submitted_at else None,
            'reviewed_by': submission.reviewed_by.get_full_name() if submission.reviewed_by else None,
            'reviewed_at': submission.reviewed_at.strftime('%B %d, %Y %I:%M %p') if submission.reviewed_at else None,
            'review_notes': submission.review_notes or '',
            'attachments': attachments,
            'last_update': submission.updated_at.strftime('%B %d, %Y %I:%M %p')
        }
        
        return JsonResponse({
            'success': True,
            'submission': data
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_http_methods(["POST"])
def update_submission(request, submission_id):
    """Update a requirement submission"""
    try:
        submission = get_object_or_404(RequirementSubmission, id=submission_id)
        
        data = json.loads(request.body)
        update_text = data.get('update_text', '').strip()
        
        if not update_text:
            return JsonResponse({
                'success': False,
                'error': 'Update text is required'
            }, status=400)
        
        # Update submission
        submission.update_text = update_text
        submission.status = 'in_progress'
        submission.updated_at = timezone.now()
        submission.save()
        
        # Log the update
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_object=submission,
            description=f"Updated requirement submission: {submission.requirement.title}"
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Submission updated successfully',
            'last_update': submission.updated_at.strftime('%B %d, %Y %I:%M %p')
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_http_methods(["POST"])
def upload_attachment(request, submission_id):
    """Upload file attachments for a submission"""
    try:
        submission = get_object_or_404(RequirementSubmission, id=submission_id)
        
        # Get uploaded files
        files = request.FILES.getlist('files')
        
        if not files:
            return JsonResponse({
                'success': False,
                'error': 'No files uploaded'
            }, status=400)
        
        uploaded_files = []
        
        for file in files:
            # Validate file size (max 5MB)
            if file.size > 5 * 1024 * 1024:
                return JsonResponse({
                    'success': False,
                    'error': f'File {file.name} is too large (max 5MB)'
                }, status=400)
            
            # Create attachment
            attachment = RequirementAttachment.objects.create(
                submission=submission,
                file=file,
                file_type=file.content_type,
                file_size=file.size,
                uploaded_by=request.user
            )
            
            uploaded_files.append({
                'id': attachment.id,
                'file_name': file.name,
                'file_size': attachment.file_size_kb,
                'file_url': attachment.file.url
            })
        
        # Log the upload
        AuditLog.objects.create(
            user=request.user,
            action='CREATE',
            content_object=submission,
            description=f"Uploaded {len(files)} file(s) for requirement: {submission.requirement.title}"
        )
        
        return JsonResponse({
            'success': True,
            'message': f'{len(files)} file(s) uploaded successfully',
            'files': uploaded_files
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_http_methods(["DELETE"])
def delete_attachment(request, attachment_id):
    """Delete a file attachment"""
    try:
        attachment = get_object_or_404(RequirementAttachment, id=attachment_id)
        submission = attachment.submission
        
        # Delete the file
        attachment.delete()
        
        # Log the deletion
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            content_object=submission,
            description=f"Deleted attachment for requirement: {submission.requirement.title}"
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Attachment deleted successfully'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_http_methods(["POST"])
def submit_to_admin(request, submission_id):
    """Submit requirement to admin for review"""
    try:
        submission = get_object_or_404(RequirementSubmission, id=submission_id)
        
        # Validate that there's content
        if not submission.update_text:
            return JsonResponse({
                'success': False,
                'error': 'Please add update details before submitting'
            }, status=400)
        
        # Update submission status
        submission.submit(request.user)
        
        return JsonResponse({
            'success': True,
            'message': 'Requirement submitted to admin successfully',
            'new_status': submission.status,
            'submitted_at': submission.submitted_at.strftime('%B %d, %Y %I:%M %p')
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_http_methods(["DELETE"])
def delete_submission(request, submission_id):
    """Delete a requirement submission"""
    try:
        submission = get_object_or_404(RequirementSubmission, id=submission_id)
        
        # Only allow deletion if status is pending
        if submission.status not in ['pending', 'in_progress']:
            return JsonResponse({
                'success': False,
                'error': 'Cannot delete submitted or reviewed requirements'
            }, status=400)
        
        requirement_title = submission.requirement.title
        
        # Log before deletion
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            description=f"Deleted requirement submission: {requirement_title}"
        )
        
        # Delete submission (attachments will be deleted via cascade)
        submission.delete()
        
        return JsonResponse({
            'success': True,
            'message': f'Requirement "{requirement_title}" deleted successfully'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


# Helper function
def calculate_due_date(period, week_number, year):
    """Calculate due date based on period and week number"""
    if period == 'weekly':
        # Calculate the last day of the specified week
        jan_1 = datetime(year, 1, 1)
        days_to_add = (week_number - 1) * 7 + (6 - jan_1.weekday())
        return (jan_1 + timedelta(days=days_to_add)).date()
    
    elif period == 'monthly':
        # Last day of current month
        if timezone.now().month == 12:
            return datetime(year + 1, 1, 1).date() - timedelta(days=1)
        else:
            return datetime(year, timezone.now().month + 1, 1).date() - timedelta(days=1)
    
    elif period == 'quarterly':
        # End of current quarter
        current_quarter = (timezone.now().month - 1) // 3
        quarter_end_month = (current_quarter + 1) * 3
        if quarter_end_month == 12:
            return datetime(year, 12, 31).date()
        else:
            return datetime(year, quarter_end_month + 1, 1).date() - timedelta(days=1)
    
    elif period == 'semestral':
        # End of semester (June 30 or December 31)
        if timezone.now().month <= 6:
            return datetime(year, 6, 30).date()
        else:
            return datetime(year, 12, 31).date()
    
    elif period == 'annually':
        # End of year
        return datetime(year, 12, 31).date()
    
    return timezone.now().date()


#DILG ADMIN
@login_required
def admin_submissions_page(request):
    """
    Admin review page - DILG STAFF ONLY
    This is where DILG admin reviews all submissions from all barangays
    """
    user_profile = request.user.userprofile
    
    # 🔒 STRICT ACCESS CONTROL - Only DILG Staff
    if user_profile.role == 'barangay official':
        messages.error(request, '🚫 Access Denied: Barangay Officials cannot access the admin review page.')
        return redirect('requirements_monitoring')  # Redirect to submission page
    
    if user_profile.role != 'dilg staff':
        messages.error(request, '🚫 Access Denied: This page is only accessible to DILG Admin.')
        return redirect('dashboard')
    
    barangays = Barangay.objects.all().order_by('name')
    
    context = {
        'barangays': barangays,
        'page_title': 'Review Submissions',
        'is_admin_view': True,  # Flag to show this is admin page
    }
    return render(request, 'admin_submissions.html', context)


@login_required
@require_http_methods(["GET"])
def api_admin_submissions_list(request):
    """
    API endpoint to get all submissions for DILG admin review
    ONLY accessible by DILG Staff
    """
    try:
        # STRICT ACCESS CONTROL
        user_profile = request.user.userprofile
        if user_profile.role != 'dilg staff':
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized: Only DILG Admin can view submissions'
            }, status=403)
        
        # Get filter parameters
        barangay_id = request.GET.get('barangay_id', '')
        status_filter = request.GET.get('status', '')
        period_filter = request.GET.get('period', '')
        search_query = request.GET.get('search', '').strip()
        
        # Base query - get ALL submissions from ALL barangays
        submissions = RequirementSubmission.objects.select_related(
            'requirement', 'barangay', 'submitted_by', 'reviewed_by'
        ).prefetch_related('attachments')
        
        # Apply filters
        if barangay_id:
            submissions = submissions.filter(barangay_id=barangay_id)
        
        if status_filter:
            submissions = submissions.filter(status=status_filter)
        else:
            # Default: show only submitted (accomplished) items awaiting review
            submissions = submissions.filter(status='accomplished')
        
        if period_filter:
            submissions = submissions.filter(requirement__period=period_filter)
        
        if search_query:
            submissions = submissions.filter(
                Q(requirement__title__icontains=search_query) |
                Q(requirement__description__icontains=search_query) |
                Q(barangay__name__icontains=search_query) |
                Q(update_text__icontains=search_query)
            )
        
        # Get statistics for all submissions
        all_submissions = RequirementSubmission.objects.all()
        
        stats = {
            'submitted': all_submissions.filter(status='accomplished').count(),
            'approved': all_submissions.filter(status='approved').count(),
            'rejected': all_submissions.filter(status='rejected').count(),
            'overdue': all_submissions.filter(
                due_date__lt=timezone.now().date(),
                status__in=['pending', 'in_progress', 'accomplished']
            ).count()
        }
        
        # Prepare submissions data
        submissions_data = []
        for sub in submissions.order_by('-submitted_at', '-updated_at'):
            # Get attachments
            attachments = []
            for att in sub.attachments.all():
                try:
                    attachments.append({
                        'id': att.id,
                        'file_name': os.path.basename(att.file.name) if att.file else 'Unknown',
                        'file_url': att.file.url if att.file else '',
                        'file_size': att.file_size_kb if hasattr(att, 'file_size_kb') else 
                                   round(att.file_size / 1024, 2) if hasattr(att, 'file_size') else 0,
                    })
                except:
                    continue
            
            submissions_data.append({
                'id': sub.id,
                'title': sub.requirement.title,
                'description': sub.requirement.description,
                'barangay_name': sub.barangay.name,
                'barangay_id': sub.barangay.id,
                'status': sub.status,
                'status_display': sub.get_status_display(),
                'period': sub.requirement.get_period_display(),
                'due_date': sub.due_date.strftime('%B %d, %Y'),
                'is_overdue': sub.is_overdue,
                'update_text': sub.update_text or '',
                'submitted_at': sub.submitted_at.strftime('%B %d, %Y') if sub.submitted_at else None,
                'submitted_by': sub.submitted_by.get_full_name() if sub.submitted_by else None,
                'reviewed_at': sub.reviewed_at.strftime('%B %d, %Y') if sub.reviewed_at else None,
                'reviewed_by': sub.reviewed_by.get_full_name() if sub.reviewed_by else None,
                'review_notes': sub.review_notes or '',
                'attachments': attachments,
            })
        
        return JsonResponse({
            'success': True,
            'submissions': submissions_data,
            'stats': stats
        })
        
    except Exception as e:
        import traceback
        print(f"=== API ADMIN SUBMISSIONS ERROR ===")
        print(f"Error: {str(e)}")
        print(f"Traceback:\n{traceback.format_exc()}")
        
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_http_methods(["POST"])
def api_admin_review_submission(request, submission_id):
    """
    FIXED: API endpoint for DILG admin to approve/reject submissions
    ONLY accessible by DILG Staff
    """
    try:
        # STRICT ACCESS CONTROL
        user_profile = request.user.userprofile
        if user_profile.role != 'dilg staff':
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized: Only DILG Admin can review submissions'
            }, status=403)
        
        submission = get_object_or_404(RequirementSubmission, id=submission_id)
        
        data = json.loads(request.body)
        action = data.get('action')  # 'approved' or 'rejected'
        review_notes = data.get('review_notes', '').strip()
        
        if action not in ['approved', 'rejected']:
            return JsonResponse({
                'success': False,
                'error': 'Invalid action. Must be "approved" or "rejected"'
            }, status=400)
        
        # Update submission
        submission.status = action
        submission.reviewed_by = request.user
        submission.reviewed_at = timezone.now()
        submission.review_notes = review_notes
        submission.save()
        
        # Log the review
        try:
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                content_object=submission,
                description=f"DILG Admin {action.upper()} submission: {submission.requirement.title} from {submission.barangay.name}"
            )
        except:
            pass
        
        return JsonResponse({
            'success': True,
            'message': f'Submission {action} successfully',
            'submission': {
                'id': submission.id,
                'status': submission.status,
                'status_display': submission.get_status_display(),
                'reviewed_by': request.user.get_full_name() or request.user.username,
                'reviewed_at': submission.reviewed_at.strftime('%B %d, %Y %I:%M %p')
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        import traceback
        print(f"=== REVIEW ERROR ===")
        print(f"Error: {str(e)}")
        print(f"Traceback:\n{traceback.format_exc()}")
        
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

def check_page_access(request, allowed_roles):
    """
    Reusable function to check if user has access to a page
    Returns: (has_access: bool, redirect_url: str or None)
    """
    if not request.user.is_authenticated:
        return False, 'login_page'
    
    try:
        user_profile = request.user.userprofile
        if user_profile.role in allowed_roles:
            return True, None
        
        # Determine where to redirect based on role
        if user_profile.role == 'dilg staff':
            return False, 'admin_submissions_page'
        elif user_profile.role == 'barangay official':
            return False, 'requirements_monitoring'
        else:
            return False, 'dashboard'
    except:
        return False, 'dashboard'
    

@login_required
@require_http_methods(["POST"])
def api_create_requirement(request):
    """
    API endpoint for DILG Admin to create new requirements
    ONLY accessible by DILG Staff
    """
    try:
        # STRICT ACCESS CONTROL
        user_profile = request.user.userprofile
        if user_profile.role != 'dilg staff':
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized: Only DILG Admin can create requirements'
            }, status=403)
        
        data = json.loads(request.body)
        
        title = data.get('title', '').strip()
        description = data.get('description', '').strip()
        period = data.get('period', '').strip()
        barangay_ids = data.get('barangay_ids', [])  # Empty = all barangays
        
        # Validation
        if not title:
            return JsonResponse({'success': False, 'error': 'Title is required'}, status=400)
        
        if not description:
            return JsonResponse({'success': False, 'error': 'Description is required'}, status=400)
        
        if not period:
            return JsonResponse({'success': False, 'error': 'Period is required'}, status=400)
        
        valid_periods = ['weekly', 'monthly', 'quarterly', 'semestral', 'annually']
        if period not in valid_periods:
            return JsonResponse({
                'success': False,
                'error': f'Invalid period. Must be one of: {valid_periods}'
            }, status=400)
        
        # Create requirement
        requirement = Requirement.objects.create(
            title=title,
            description=description,
            period=period,
            created_by=request.user,
            is_active=True
        )
        
        # Assign to specific barangays if provided, otherwise applies to all
        if barangay_ids:
            target_barangays = Barangay.objects.filter(id__in=barangay_ids)
            requirement.applicable_barangays.set(target_barangays)
        else:
            # If no specific barangays, get all
            target_barangays = Barangay.objects.all()
        
        # 🔥 FIX: AUTO-CREATE SUBMISSIONS FOR ALL BARANGAYS
        current_year = timezone.now().year
        submissions_created = 0
        
        for barangay in target_barangays:
            if period == 'weekly':
                # Create submissions for the next 4 weeks
                for week_num in range(1, 5):
                    RequirementSubmission.objects.create(
                        requirement=requirement,
                        barangay=barangay,
                        week_number=week_num,
                        year=current_year,
                        due_date=calculate_due_date(period, week_num, current_year),
                        status='pending'
                    )
                    submissions_created += 1
            else:
                # For monthly, quarterly, semestral, annually - create one submission
                RequirementSubmission.objects.create(
                    requirement=requirement,
                    barangay=barangay,
                    week_number=None,
                    year=current_year,
                    due_date=calculate_due_date(period, 1, current_year),
                    status='pending'
                )
                submissions_created += 1
        
        print(f"✅ Created {submissions_created} submissions for requirement: {title}")
        
        # Log the creation
        try:
            AuditLog.objects.create(
                user=request.user,
                action='CREATE',
                content_object=requirement,
                description=f"DILG Admin created new requirement: {title} with {submissions_created} submissions"
            )
        except:
            pass
        
        return JsonResponse({
            'success': True,
            'message': f'Requirement created successfully! {submissions_created} submissions created for barangays.',
            'requirement': {
                'id': requirement.id,
                'title': requirement.title,
                'description': requirement.description,
                'period': requirement.period,
                'period_display': requirement.get_period_display(),
                'submissions_created': submissions_created,
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        import traceback
        print(f"=== CREATE REQUIREMENT ERROR ===")
        print(f"Error: {str(e)}")
        print(f"Traceback:\n{traceback.format_exc()}")
        
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def api_edit_requirement(request, requirement_id):
    """
    API endpoint for DILG Admin to edit existing requirements
    ONLY accessible by DILG Staff
    """
    try:
        user_profile = request.user.userprofile
        if user_profile.role != 'dilg staff':
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized: Only DILG Admin can edit requirements'
            }, status=403)
        
        requirement = get_object_or_404(Requirement, id=requirement_id)
        
        data = json.loads(request.body)
        
        title = data.get('title', '').strip()
        description = data.get('description', '').strip()
        period = data.get('period', '').strip()
        is_active = data.get('is_active', True)
        
        if title:
            requirement.title = title
        if description:
            requirement.description = description
        if period:
            requirement.period = period
        
        requirement.is_active = is_active
        requirement.save()
        
        # Log the update
        try:
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                content_object=requirement,
                description=f"DILG Admin updated requirement: {requirement.title}"
            )
        except:
            pass
        
        return JsonResponse({
            'success': True,
            'message': 'Requirement updated successfully'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)



@login_required
@require_http_methods(["DELETE"])
def api_delete_requirement(request, requirement_id):
    """
    API endpoint for DILG Admin to delete requirements
    ONLY accessible by DILG Staff
    """
    try:
        user_profile = request.user.userprofile
        if user_profile.role != 'dilg staff':
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized: Only DILG Admin can delete requirements'
            }, status=403)
        
        requirement = get_object_or_404(Requirement, id=requirement_id)
        title = requirement.title
        
        # Log before deletion
        try:
            AuditLog.objects.create(
                user=request.user,
                action='DELETE',
                description=f"DILG Admin deleted requirement: {title}"
            )
        except:
            pass
        
        requirement.delete()
        
        return JsonResponse({
            'success': True,
            'message': f'Requirement "{title}" deleted successfully'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)



@login_required
@require_http_methods(["GET"])
def api_all_requirements(request):
    """
    API endpoint to get all requirements (for DILG Admin management)
    ONLY accessible by DILG Staff
    """
    try:
        user_profile = request.user.userprofile
        if user_profile.role != 'dilg staff':
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized'
            }, status=403)
        
        requirements = Requirement.objects.all().order_by('-created_at')
        
        requirements_data = []
        for req in requirements:
            applicable_barangays = list(req.applicable_barangays.values_list('name', flat=True))
            
            requirements_data.append({
                'id': req.id,
                'title': req.title,
                'description': req.description,
                'period': req.period,
                'period_display': req.get_period_display(),
                'is_active': req.is_active,
                'applicable_barangays': applicable_barangays if applicable_barangays else ['All Barangays'],
                'created_at': req.created_at.strftime('%B %d, %Y'),
                'created_by': req.created_by.get_full_name() if req.created_by else 'System',
            })
        
        return JsonResponse({
            'success': True,
            'requirements': requirements_data
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
    



#-------------------ANNOUNCEMENTS AND NOTIFICATIONS------------
@login_required
def delete_announcement(request, announcement_id):
    """Delete an announcement"""
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'error': 'Only POST requests are allowed'
        }, status=405)
    
    try:
        print(f"Attempting to delete announcement with ID: {announcement_id}")
        
        # Get the announcement
        announcement = Announcement.objects.get(id=announcement_id)
        print(f"Found announcement: {announcement.title}")
        
        # Store info before deletion
        title = announcement.title
        
        # Delete the announcement
        announcement.delete()
        print(f"Successfully deleted announcement: {title}")
        
        return JsonResponse({
            'success': True,
            'message': f'Announcement "{title}" deleted successfully'
        })
        
    except Announcement.DoesNotExist:
        print(f"Announcement with ID {announcement_id} does not exist")
        return JsonResponse({
            'success': False,
            'error': 'Announcement not found'
        }, status=404)
        
    except Exception as e:
        # Log the full error for debugging
        error_details = traceback.format_exc()
        print(f"Error deleting announcement {announcement_id}:")
        print(error_details)
        
        return JsonResponse({
            'success': False,
            'error': f'Server error: {str(e)}'
        }, status=500)

@login_required
@require_POST
def update_announcement(request, announcement_id):
    """Update an existing announcement"""
    try:
        announcement = Announcement.objects.get(id=announcement_id)
        data = json.loads(request.body)
        
        # Update fields
        announcement.title = data.get('title', announcement.title)
        announcement.content = data.get('content', announcement.content)
        announcement.priority = data.get('priority', announcement.priority)
        announcement.save()
        
        notifications_sent = 0
        send_notification = data.get('send_notification', False)
        
        # Send update notifications if enabled
        if send_notification:
            barangay_users = User.objects.filter(
                userprofile__role='barangay official',
                is_active=True
            ).distinct()
            
            notification_list = []
            for user in barangay_users:
                notification_list.append(
                    Notification(
                        user=user,
                        title=f"📢 Updated: {announcement.title}",
                        message=f"An announcement has been updated: {announcement.content[:100]}...",
                        notification_type='info',
                        created_at=timezone.now()
                    )
                )
            
            Notification.objects.bulk_create(notification_list)
            notifications_sent = len(notification_list)
        
        return JsonResponse({
            'success': True,
            'announcement': {
                'id': announcement.id,
                'title': announcement.title,
                'content': announcement.content,
                'priority': announcement.priority
            },
            'notifications_sent': notifications_sent
        })
        
    except Announcement.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Announcement not found'
        }, status=404)
    except Exception as e:
        import traceback
        print(f"=== UPDATE ANNOUNCEMENT ERROR ===")
        print(f"Error: {str(e)}")
        print(f"Traceback:\n{traceback.format_exc()}")
        
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
    
@login_required
@require_http_methods(["GET"])
def get_announcements(request):
    """Get all announcements"""
    try:
        announcements = Announcement.objects.all().select_related('posted_by').order_by('-posted_at')
        
        announcements_list = []
        for announcement in announcements:
            announcements_list.append({
                'id': announcement.id,
                'title': announcement.title,
                'content': announcement.content,
                'priority': announcement.priority,
                'priority_display': announcement.get_priority_display(),
                'posted_by': announcement.posted_by.get_full_name() or announcement.posted_by.username,
                'posted_at': announcement.posted_at.strftime('%B %d, %Y'),
                'views': announcement.views,
                'sent_to_barangays': 33  
            })
        
        return JsonResponse({
            'success': True,
            'announcements': announcements_list
        })
        
    except Exception as e:
        import traceback
        print(f"=== GET ANNOUNCEMENTS ERROR ===")
        print(f"Error: {str(e)}")
        print(f"Traceback:\n{traceback.format_exc()}")
        
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
    
@login_required
def debug_users(request):
    """Debug view to see all users and their roles"""
    users = User.objects.all()
    
    user_list = []
    for user in users:
        try:
            role = user.userprofile.role if hasattr(user, 'userprofile') else 'No profile'
        except:
            role = 'Error getting role'
        
        user_list.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'is_superuser': user.is_superuser,
            'role': role
        })
    
    return JsonResponse({
        'total_users': users.count(),
        'users': user_list
    }, json_dumps_params={'indent': 2})

#-----------------END OF ANNOUNCEMENTS AND NOTIFICATIONS--------

#---------------NOTIFICATIONS----------------------
@login_required
@require_http_methods(["GET"])
def get_notifications(request):
    """Get all notifications for the current user"""
    try:
        notifications = Notification.objects.filter(
            user=request.user
        ).select_related('submission', 'submission__requirement', 'submission__barangay').order_by('-created_at')
        
        unread_count = notifications.filter(is_read=False).count()
        
        notification_list = []
        for notif in notifications[:50]:
            notification_data = {
                'id': notif.id,
                'title': notif.title,
                'message': notif.message,
                'type': notif.notification_type,
                'is_read': notif.is_read,
                'created_at': notif.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'time_ago': get_time_ago(notif.created_at),
            }
            
            if notif.submission:
                notification_data['submission'] = {
                    'id': notif.submission.id,
                    'requirement_name': notif.submission.requirement.title,
                    'barangay_name': notif.submission.barangay.name,
                    'status': notif.submission.status,
                    'due_date': notif.submission.due_date.strftime('%Y-%m-%d'),
                }
            
            notification_list.append(notification_data)
        
        return JsonResponse({
            'success': True,
            'notifications': notification_list,
            'unread_count': unread_count,
            'total_count': notifications.count()
        })
        
    except Exception as e:
        print(f"Error in get_notifications: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def mark_notification_read(request, notification_id):
    """Mark a single notification as read"""
    try:
        notification = Notification.objects.get(
            id=notification_id,
            user=request.user
        )
        notification.is_read = True
        notification.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Notification marked as read'
        })
        
    except Notification.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Notification not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_http_methods(["POST"])
def mark_all_notifications_read(request):
    """Mark all notifications as read for current user"""
    try:
        updated = Notification.objects.filter(
            user=request.user,
            is_read=False
        ).update(is_read=True)
        
        return JsonResponse({
            'success': True,
            'message': f'{updated} notifications marked as read'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_http_methods(["GET"])
def get_unread_count(request):
    """Get count of unread notifications"""
    try:
        count = Notification.objects.filter(
            user=request.user,
            is_read=False
        ).count()
        
        return JsonResponse({
            'success': True,
            'unread_count': count
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
    
@login_required
@require_POST
def create_announcement(request):
    """Create a new announcement and send notifications to barangays"""
    try:
        data = json.loads(request.body)
        
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        priority = data.get('priority', 'medium')
        send_notification = data.get('send_notification', False)
        
        # Validation
        if not title or not content:
            return JsonResponse({
                'success': False,
                'error': 'Title and content are required'
            }, status=400)
        
        # Create announcement
        announcement = Announcement.objects.create(
            title=title,
            content=content,
            priority=priority,
            posted_by=request.user,
            posted_at=timezone.now()
        )
        
        notifications_sent = 0
        
        # Send notifications to all barangay users if enabled
        if send_notification:
            # FIX: Get ALL active users (or all users with 'barangay official' role)
            # Option 1: Send to all active users
            barangay_users = User.objects.filter(
                is_active=True,
                is_superuser=False  # Exclude admin from notifications
            ).exclude(
                id=request.user.id  # Exclude the person posting
            ).distinct()
            
            # Debug: Print how many users we found
            print(f"📊 Found {barangay_users.count()} users to notify")
            for user in barangay_users:
                try:
                    role = user.userprofile.role if hasattr(user, 'userprofile') else 'No role'
                    print(f"   - {user.username}: {role}")
                except:
                    print(f"   - {user.username}: No profile")
            
            # Create notification for each user
            notification_list = []
            for user in barangay_users:
                notification_list.append(
                    Notification(
                        user=user,
                        title=f"📢 New Announcement: {title}",
                        message=f"{content[:100]}..." if len(content) > 100 else content,
                        notification_type='info',
                        announcement=announcement,
                        created_at=timezone.now()
                    )
                )
            
            # Bulk create notifications for efficiency
            if notification_list:
                Notification.objects.bulk_create(notification_list)
                notifications_sent = len(notification_list)
                print(f"✅ Created {notifications_sent} notifications")
        
        return JsonResponse({
            'success': True,
            'announcement': {
                'id': announcement.id,
                'title': announcement.title,
                'content': announcement.content,
                'priority': announcement.priority,
                'posted_at': announcement.posted_at.strftime('%B %d, %Y'),
                'posted_by': announcement.posted_by.get_full_name() or announcement.posted_by.username
            },
            'notifications_sent': notifications_sent
        })
        
    except Exception as e:
        import traceback
        print(f"=== CREATE ANNOUNCEMENT ERROR ===")
        print(f"Error: {str(e)}")
        print(f"Traceback:\n{traceback.format_exc()}")
        
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

    
@login_required
@require_http_methods(["POST"])
def submit_requirement_with_notification(request, submission_id):
    """Handle requirement submission and create notifications"""
    try:
        submission = RequirementSubmission.objects.get(
            id=submission_id,
            barangay__user=request.user
        )
        
        # Update submission status
        submission.status = 'accomplished'
        submission.submitted_at = timezone.now()
        submission.save()
        
        # Create notification for admins
        create_admin_notification(
            title="New Submission for Review",
            message=f"{submission.barangay.name} submitted {submission.requirement.title}",
            notification_type='info',
            submission=submission
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Requirement submitted successfully',
            'submission': {
                'id': submission.id,
                'status': submission.status,
                'status_display': submission.get_status_display(),
                'submitted_at': submission.submitted_at.strftime('%B %d, %Y')
            }
        })
        
    except RequirementSubmission.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Submission not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def approve_submission_with_notification(request, submission_id):
    """Approve submission and notify submitter"""
    try:
        # Check if user is admin
        if not (request.user.groups.filter(name='Admin').exists() or request.user.is_superuser):
            return JsonResponse({
                'success': False,
                'error': 'Permission denied'
            }, status=403)
        
        submission = RequirementSubmission.objects.get(id=submission_id)
        
        # Get review notes if any
        import json
        data = json.loads(request.body) if request.body else {}
        review_notes = data.get('review_notes', '')
        
        # Update submission
        submission.status = 'approved'
        submission.reviewed_by = request.user
        submission.reviewed_at = timezone.now()
        submission.review_notes = review_notes
        submission.save()
        
        # Create notification for submitter
        message = f"Your submission for {submission.requirement.title} has been approved"
        if review_notes:
            message += f". Admin notes: {review_notes}"
        
        create_notification(
            user=submission.barangay.user,
            title="Submission Approved",
            message=message,
            notification_type='completed',
            submission=submission
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Submission approved successfully'
        })
        
    except RequirementSubmission.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Submission not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def reject_submission_with_notification(request, submission_id):
    """Reject submission and notify submitter"""
    try:
        # Check if user is admin
        if not (request.user.groups.filter(name='Admin').exists() or request.user.is_superuser):
            return JsonResponse({
                'success': False,
                'error': 'Permission denied'
            }, status=403)
        
        submission = RequirementSubmission.objects.get(id=submission_id)
        
        # Get review notes
        import json
        data = json.loads(request.body) if request.body else {}
        review_notes = data.get('review_notes', '')
        
        # Update submission
        submission.status = 'rejected'
        submission.reviewed_by = request.user
        submission.reviewed_at = timezone.now()
        submission.review_notes = review_notes
        submission.save()
        
        # Create notification for submitter
        message = f"Your submission for {submission.requirement.title} needs revision"
        if review_notes:
            message += f". Admin notes: {review_notes}"
        
        create_notification(
            user=submission.barangay.user,
            title="Submission Needs Revision",
            message=message,
            notification_type='overdue',
            submission=submission
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Submission rejected successfully'
        })
        
    except RequirementSubmission.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Submission not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


def get_time_ago(datetime_obj):
    """Convert datetime to 'time ago' format"""
    from django.utils import timezone
    now = timezone.now()
    diff = now - datetime_obj
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "Just now"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif seconds < 604800:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days > 1 else ''} ago"
    else:
        weeks = int(seconds / 604800)
        return f"{weeks} week{'s' if weeks > 1 else ''} ago"

def create_notification(user, title, message, notification_type, submission=None):
    """Helper function to create notifications"""
    try:
        notification = Notification.objects.create(
            user=user,
            title=title,
            message=message,
            notification_type=notification_type,
            submission=submission
        )
        return notification
    except Exception as e:
        print(f"Error creating notification: {e}")
        return None


def create_admin_notification(title, message, notification_type, submission=None):
    """Create notification for all admin users"""
    from django.contrib.auth import get_user_model
    User = get_user_model()
    
    try:
        # Get all admin users
        admin_users = User.objects.filter(
            Q(is_superuser=True) | Q(groups__name='Admin')
        ).distinct()
        
        # Create notification for each admin
        notifications = []
        for admin in admin_users:
            notif = create_notification(
                user=admin,
                title=title,
                message=message,
                notification_type=notification_type,
                submission=submission
            )
            if notif:
                notifications.append(notif)
        
        return notifications
        
    except Exception as e:
        print(f"Error creating admin notifications: {e}")
        return []

#----END OF NOTIFICATIONS HELPERS----
