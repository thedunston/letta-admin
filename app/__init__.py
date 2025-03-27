"""
Main application module for the admin interface.
"""

from flask import Flask

from .config.settings import (PERMANENT_SESSION_LIFETIME, SECRET_KEY,
                              SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SECURE)
from .routes.routes import register_routes


def create_app():
    """
    Create and configure the Flask application.
    
    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__, 
                static_folder='static',  # Serve static files from app/static
                static_url_path='/static')  # URL path for static files
    
    # Configure Flask app
    app.secret_key = SECRET_KEY
    app.config['SESSION_COOKIE_HTTPONLY'] = SESSION_COOKIE_HTTPONLY
    app.config['PERMANENT_SESSION_LIFETIME'] = PERMANENT_SESSION_LIFETIME
    app.config['SESSION_COOKIE_SECURE'] = SESSION_COOKIE_SECURE
    
    # Register routes
    register_routes(app)
    
    return app 