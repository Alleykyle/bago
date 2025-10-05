from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

def role_required(*allowed_roles):
    """
    Restrict access to users with specific roles.
    Usage: @role_required('dilg staff', 'municipal officer')
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.error(request, "You must be logged in to access this page.")
                return redirect('login_page')
            
            # Get role from UserProfile
            try:
                role = request.user.userprofile.role.strip().lower()
            except:
                messages.error(request, "Your account has no role assigned. Contact admin.")
                return redirect('landing_page')

            # Normalize allowed roles for comparison
            allowed_roles_normalized = [r.strip().lower() for r in allowed_roles]

            if role not in allowed_roles_normalized:
                messages.error(request, "You are not authorized to access this page.")
                return redirect('landing_page')

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
