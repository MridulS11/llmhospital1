# core/templatetags/custom_filters.py
from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)

@register.filter
def group_fullname(code):
    code = code.upper()
    mapping = {
        'JD': 'Junior Doctor',
        'SD': 'Senior Doctor',
        'MG': 'Manager',
        'AM': 'Assistant Manager',
        'CM': 'Chemist',
        'RC': 'Receptionist',
        'FN': 'Finance',
    }
    return mapping.get(code, code)