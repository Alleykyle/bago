from django.http import HttpResponseForbidden
from functools import wraps
from django.contrib.auth.decorators import login_required


def role_required(*required_roles):
    """
    Decorator for views that checks whether a user has one of the allowed roles.
    Usage:
        @role_required('role1', 'role2')
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            try:
                user_role = request.user.userprofile.role.strip().lower()
            except Exception:
                return HttpResponseForbidden("User role not found.")

            normalized_roles = [r.strip().lower() for r in required_roles]

            if user_role not in normalized_roles:
                return HttpResponseForbidden("You do not have permission to access this page.")

            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


