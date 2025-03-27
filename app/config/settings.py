"""
Configuration settings for the admin interface.
"""

import os
import tempfile
from datetime import timedelta

# Create a temporary directory using Python's tempfile module
TEMP_DIR = os.path.join(tempfile.gettempdir(), 'code_execution')
try:
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR, mode=0o777, exist_ok=True)
    # Ensure directory has proper permissions
    os.chmod(TEMP_DIR, 0o777)
except Exception as e:
    print(f"Warning: Could not create or set permissions for temp directory: {e}")
    # Fallback to a local temp directory if system temp is not accessible
    TEMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'temp_code_execution')
    os.makedirs(TEMP_DIR, mode=0o777, exist_ok=True)

# Flask settings
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev')  # Should be set in production
SESSION_COOKIE_HTTPONLY = True
PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
SESSION_COOKIE_SECURE = not os.environ.get('FLASK_DEBUG', False)

# Proxy settings
DEFAULT_PROXY_URL = os.environ.get('PROXY_URL', 'http://localhost:8284')

# Code execution settings
CODE_SIZE_LIMIT = 10000  # 10KB
EXECUTION_TIMEOUT = 30  # seconds
MAX_OUTPUT_SIZE = 50000  # characters 