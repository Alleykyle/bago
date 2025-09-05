from django import template
import json
import pprint

register = template.Library()

@register.filter
def pprint(value):
    """Pretty print JSON data for template display"""
    if not value:
        return ''
    
    try:
        if isinstance(value, dict):
            # Format dictionary nicely
            formatted = ""
            for key, val in value.items():
                if key == 'csrfmiddlewaretoken':
                    continue  # Skip CSRF tokens
                
                # Truncate long values
                if isinstance(val, str) and len(val) > 100:
                    val = val[:100] + "..."
                
                formatted += f"{key}: {val}\n"
            return formatted.strip()
        
        elif isinstance(value, str):
            try:
                parsed = json.loads(value)
                return json.dumps(parsed, indent=2)
            except:
                return value
        
        else:
            return str(value)
            
    except Exception:
        return str(value)

@register.filter
def format_action(action):
    """Format action type for display"""
    action_icons = {
        'CREATE': '➕ Create',
        'UPDATE': '✏️ Update', 
        'DELETE': '🗑️ Delete',
        'LOGIN': '🔐 Login',
        'LOGOUT': '🚪 Logout',
        'VIEW': '👁️ View',
        'SEARCH': '🔍 Search',
        'EXPORT': '📤 Export',
        'IMPORT': '📥 Import',
        'BULK_OPERATION': '📊 Bulk Operation',
        'SECURITY_ALERT': '🚨 Security Alert',
        'PAGE_VIEW': '📄 Page View',
        'FORM_SUBMIT': '📝 Form Submit',
    }
    
    return action_icons.get(action, f'• {action.title()}')

@register.filter
def time_since_short(timestamp):
    """Short format for time since"""
    from django.utils import timezone
    from datetime import timedelta
    
    now = timezone.now()
    diff = now - timestamp
    
    if diff.days > 0:
        return f"{diff.days}d ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours}h ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes}m ago"
    else:
        return "Just now"

@register.filter
def user_display(user):
    """Display user name or 'System' if None"""
    if not user:
        return 'System'
    
    # Try to get full name, fallback to username
    if hasattr(user, 'get_full_name') and user.get_full_name():
        return user.get_full_name()
    
    return user.username

@register.filter 
def truncate_json(value, length=200):
    """Truncate JSON values for display"""
    if not value:
        return ''
    
    str_value = str(value)
    if len(str_value) <= length:
        return str_value
    
    return str_value[:length] + '...'