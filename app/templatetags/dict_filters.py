from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """
    Template filter to get dictionary value by key
    Usage: {{ my_dict|get_item:my_key }}
    """
    if dictionary is None:
        return None
    if not isinstance(dictionary, dict):
        return None
    return dictionary.get(key)

@register.filter
def get_barangay_color(barangay_statuses, barangay_id):
    """
    Get the color for a barangay
    Usage: {{ barangay_statuses|get_barangay_color:barangay.id }}
    """
    if not barangay_statuses or barangay_id not in barangay_statuses:
        return 'gray'
    return barangay_statuses[barangay_id].get('color', 'gray')

@register.filter
def get_barangay_tooltip(barangay_statuses, barangay_id):
    """
    Get the tooltip for a barangay
    Usage: {{ barangay_statuses|get_barangay_tooltip:barangay.id }}
    """
    if not barangay_statuses or barangay_id not in barangay_statuses:
        return 'No data'
    return barangay_statuses[barangay_id].get('tooltip', 'No data')
