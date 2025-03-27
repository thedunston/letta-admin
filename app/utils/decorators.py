"""
Decorators for common functionality.
"""

from functools import wraps
from flask import redirect, url_for, request, jsonify
from ..auth.auth import check_session_valid
from .session import get_proxy_url

def require_login(f):
    """
    Decorator to require user login for a route.
    Redirects to login page if not authenticated.
    
    Args:
        f: The route function to decorate
        
    Returns:
        function: The decorated route function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_session_valid():
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def require_json(f):
    """
    Decorator to require JSON content type for a route.
    Returns 400 error if content type is not application/json.
    
    Args:
        f: The route function to decorate
        
    Returns:
        function: The decorated route function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json.'}), 400
        return f(*args, **kwargs)
    return decorated_function

def with_proxy_url(f):
    """
    Decorator to inject proxy URL into route function.
    Adds proxy_url parameter to function call.
    
    Args:
        f: The route function to decorate
        
    Returns:
        function: The decorated route function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        kwargs['proxy_url'] = get_proxy_url()
        return f(*args, **kwargs)
    return decorated_function 