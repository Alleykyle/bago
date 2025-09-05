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

        if user is not None:
            if user.is_active:
                login(request, user)
                
                # Get client info
                ip_address = get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                
                # Update profile login info
                try:
                    profile = user.userprofile
                    if hasattr(profile, 'update_login_info'):
                        profile.update_login_info(ip_address)
                    
                    # Create audit log
                    try:
                        AuditLog.objects.create(
                            user=user,
                            action='LOGIN',
                            ip_address=ip_address,
                            user_agent=user_agent,
                            description=f"User {username} logged in successfully"
                        )
                    except:
                        pass  # Skip audit logging if AuditLog doesn't exist
                    
                    role = profile.role.strip().lower()
                    
                    if role == 'barangay official':
                        return redirect('civil_service_certification')
                    elif role == 'municipal officer':
                        return redirect('requirements_monitoring')
                    elif role == 'dilg staff':
                        return redirect('landing_menu')
                    else:
                        return redirect('landing_page')
                        
                except UserProfile.DoesNotExist:
                    messages.error(request, 'User profile not found. Contact admin.')
                    return redirect('login_page')
            else:
                messages.error(request, 'Account inactive. Please contact support.')
        else:
            # Log failed login attempt
            try:
                AuditLog.objects.create(
                    action='LOGIN',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    description=f"Failed login attempt for username: {username}"
                )
            except:
                pass  # Skip audit logging if AuditLog doesn't exist
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login_page.html')


def landing_menu(request):
    return render(request, 'landing_menu.html')


@login_required
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


def requirements_monitoring(request):
    return render(request, 'requirements_monitoring.html')


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



@login_required
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
    
    