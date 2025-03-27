"""
Authentication module for the admin interface.
"""

import hashlib
import secrets
import time

import requests
from flask import session, url_for

from ..config.settings import DEFAULT_PROXY_URL
from ..utils.session import get_proxy_url


def hash_password(password):
    """
    Hash a password using SHA-256 algorithm.
    
    Args:
        password (str): The plain text password to hash.
        
    Returns:
        str: The hashed password as a hexadecimal string.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def check_session_valid():
    """
    Check if the current session is valid.
    
    Returns:
        bool: True if session is valid, False otherwise.
    """
    if 'admin_logged_in' not in session:
        return False
    
    # Check if session has expired (1 hour timeout)
    last_activity = session.get('last_activity', 0)
    current_time = int(time.time())
    time_diff = current_time - last_activity
    
    if time_diff > 3600:  # 1 hour in seconds
        session.clear()
        return False
    
    # Update last activity time
    session['last_activity'] = current_time
    return True

def login(username, password, proxy_url=None):
    """
    Handle user login.
    
    Args:
        username (str): Username
        password (str): Password
        proxy_url (str, optional): Proxy URL. Defaults to DEFAULT_PROXY_URL.
        
    Returns:
        tuple: (success, message, redirect_url)
    """
    proxy_url = proxy_url or DEFAULT_PROXY_URL
    proxy_url = proxy_url.rstrip('/')
    password_hash = hash_password(password)
    
    try:
        # Get user identity from API
        response = requests.get(f'{proxy_url}/identities/')
        identities = response.json()
        
        # Find matching identity
        user_identity = next(
            (identity for identity in identities 
             if identity['name'] == username),
            None
        )
        
        if user_identity:
            # Get stored password hash
            stored_password = next(
                (prop['value'] for prop in user_identity['properties']
                 if prop['key'] == 'password'),
                None
            )
            
            if stored_password == password_hash:
                new_token = secrets.token_urlsafe(32)
                
                update_data = {
                    "properties": [
                        {
                            "key": "token",
                            "value": new_token,
                            "type": "string"
                        }
                    ]
                }

                # Update token in identity API
                token_response = requests.patch(
                    f'{proxy_url}/identities/{user_identity["id"]}',
                    json=update_data
                )
                
                if token_response.status_code == 200:
                    # Set session data
                    session.permanent = True
                    session['admin_logged_in'] = True
                    session['admin_username'] = username
                    session['admin_token'] = new_token
                    session['identity_id'] = user_identity['id']
                    session['proxy_url'] = proxy_url
                    session['last_activity'] = int(time.time())
                    
                    return True, "Login successful", url_for('admin_dashboard')
                else:
                    return False, "Failed to update authentication token", None
            else:
                return False, "Invalid credentials", None
        else:
            return False, "Invalid credentials", None
            
    except requests.exceptions.RequestException as e:
        return False, "Service temporarily unavailable", None
    except Exception as e:
        return False, "An error occurred", None

def logout():
    """
    Handle user logout.
    
    Returns:
        tuple: (success, message, redirect_url)
    """
    if 'identity_id' in session:
        try:
            # Clear token in identity properties
            update_data = {
                "properties": [
                    {
                        "key": "token",
                        "value": "",
                        "type": "string"
                    }
                ]
            }
            requests.patch(
                f'{get_proxy_url()}/identities/{session["identity_id"]}',
                json=update_data
            )
        except:
            pass
            
    session.clear()
    return True, "Logged out successfully", url_for('admin_login') 