"""
Utility functions for handling session data.
"""

from flask import session
from ..config.settings import DEFAULT_PROXY_URL

def get_proxy_url():
    """
    Get the proxy URL from the session, falling back to the default if not set.
    
    Returns:
        str: The proxy URL
    """
    return session.get('proxy_url', DEFAULT_PROXY_URL) 