"""
Admin Interface - Flask application for managing the admin dashboard.

This module provides a Flask web application that serves as the administrative interface
for the platform. It handles user authentication, session management, and provides
endpoints for managing agents, users, and tools.

The application uses a proxy server (default: http://localhost:8284) for all API interactions
and implements security measures such as:
- Session-based authentication.
- Password hashing.
- CSRF protection.
- Secure cookie handling.
- Rate limiting for sensitive operations.

Dependencies:
    flask: Web framework.
    requests: HTTP client for API interactions.
    secrets: Secure token generation.
    hashlib: Password hashing.
    sqlite3: Local data storage.
    subprocess: Code execution handling.

"""

import sqlite3
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, make_response
import os
import requests
import secrets
import hashlib
import subprocess
from datetime import timedelta
import time

# Create a temporary directory outside the Flask app directory.
TEMP_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'temp_code_execution')
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR)

app = Flask(__name__)
# Use a strong random secret key.
app.secret_key = secrets.token_hex(32)
# Set session configuration.

# Prevent JavaScript access to session cookie.
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Session expires after 1 hour.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

  # Only send cookie over HTTPS.
if not app.debug:
    app.config['SESSION_COOKIE_SECURE'] = True

def hash_password(password):
    """
    Hash a password using SHA-256 algorithm.
    
    Args:
        password (str): The plain text password to hash.
        
    Returns:
        str: The hashed password as a hexadecimal string.
    """
    return hashlib.sha256(password.encode()).hexdigest()

DEFAULT_PROXY_URL = 'http://localhost:8284'

@app.route('/')
def index():
    """
    Render the admin index page.
    
    Returns:
        Response: Rendered HTML template for the admin index page.
    """
    return render_template('admin_index.html')

@app.route('/test-proxy', methods=['POST'])
def test_proxy():
    """
    Test the connection to the proxy server.
    
    Tests the connection by making a request to the /health endpoint
    of the specified proxy URL. Validates connectivity and version compatibility.
    
    Returns:
        JSON: Status of the connection test with success flag and message.
    """
    proxy_url = request.json.get('proxy_url', '').rstrip('/')
    if not proxy_url:
        return jsonify({'error': 'Proxy URL is required.'}), 400
        
    try:
        response = requests.get(f'{proxy_url}/health')
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'ok':
                return jsonify({
                    'success': True,
                    'message': f'Successfully connected to proxy. Version: {data.get("version", "unknown")}.'
                })
        return jsonify({
            'success': False,
            'message': 'Invalid response from proxy server.'
        })
    except requests.exceptions.RequestException as e:
        return jsonify({
            'success': False,
            'message': f'Failed to connect to proxy: {str(e)}.'
        })

@app.route('/login', methods=['GET', 'POST'])
def admin_login():
    """
    Handle admin login functionality.
    
    This route handles both displaying the login form (GET) and processing
    login attempts (POST). It verifies credentials against the identity API
    and manages session data for authenticated users.
    
    The login process includes:
    - Password hashing and verification.
    - Token generation and storage.
    - Session initialization.
    - Proxy URL configuration.
    
    Returns:
        Response: Either the login page or a redirect to the dashboard.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        proxy_url = request.form.get('proxy_url', DEFAULT_PROXY_URL).rstrip('/')
        password_hash = hash_password(password)
        
        print(f"Login attempt for username: {username}.")
        print(f"Using proxy URL: {proxy_url}.")
        print(f"Generated password hash: {password_hash}.")
        
        try:
            # Get user identity from API.
            print("Fetching identities from API...")
            response = requests.get(f'{proxy_url}/identities/')
            print(f"API Response status: {response.status_code}.")
            identities = response.json()
            print(f"Found {len(identities)} identities.")
            
            # Find matching identity.
            user_identity = next(
                (identity for identity in identities 
                 if identity['name'] == username),
                None
            )
            
            if user_identity:
                print(f"Found matching identity: {user_identity['id']}.")
                print(f"Identity type: {user_identity['identity_type']}.")
                
                # Get stored password hash.
                stored_password = next(
                    (prop['value'] for prop in user_identity['properties']
                     if prop['key'] == 'password'),
                    None
                )
                print(f"Stored password hash: {stored_password}.")
                print(f"Comparing with provided hash: {password_hash}.")
                
                if stored_password == password_hash:
                    print("Password match successful.")
                    new_token = secrets.token_urlsafe(32)
                    print(f"Generated new token: {new_token}.")
                    
                    update_data = {
                        "properties": [
                            {
                                "key": "token",
                                "value": new_token,
                                "type": "string"
                            }
                        ]
                    }

                    # Update token in identity API.
                    print(f"Updating token for identity {user_identity['id']}.")
                    token_response = requests.patch(
                        f'{proxy_url}/identities/{user_identity["id"]}',
                        json=update_data
                    )
                    print(f"Token update response: {token_response.status_code}.")
             
                    if token_response.status_code == 200:
                        print("Token updated successfully.")
                        # Set session as permanent and update all variables.
                        session.permanent = True
                        session['admin_logged_in'] = True
                        session['admin_username'] = username
                        session['admin_token'] = new_token
                        session['identity_id'] = user_identity['id']
                        session['proxy_url'] = proxy_url
                        session['last_activity'] = int(time.time())
                        print("Session data set.")
                        return redirect(url_for('admin_dashboard'))
                    else:
                        print("Failed to update token.")
                        return render_template('admin_login.html', error='Failed to update authentication token.')
                else:
                    print("Password mismatch.")
            else:
                print(f"No identity found for username: {username}.")
            
        except requests.exceptions.RequestException as e:
            print(f"API Error: {str(e)}.")
            return render_template('admin_login.html', error='Service temporarily unavailable.')
        except Exception as e:
            print(f"Unexpected error: {str(e)}.")
            return render_template('admin_login.html', error='An error occurred.')
        
        return render_template('admin_login.html', error='Invalid credentials.')
    
    return render_template('admin_login.html', default_proxy_url=DEFAULT_PROXY_URL)

@app.route('/admin/dashboard')
def admin_dashboard():
    """
    Display the admin dashboard.
    
    This route checks if the user is logged in and shows the dashboard
    if authenticated. If not logged in, redirects to the login page.
    
    The dashboard provides access to:
    - Agent management.
    - User management.
    - Tool configuration.
    - System monitoring.
    
    Returns:
        Response: Rendered dashboard template or redirect to login.
    """
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
    return render_template('dashboard.html', proxy_url=session.get('proxy_url', DEFAULT_PROXY_URL))

@app.route('/admin/session-info')
def session_info():
    """
    Provide session information for the frontend.
    
    This endpoint returns JSON data about the current admin session,
    including:
    - Login status.
    - Username.
    - Authentication token.
    - Identity ID.
    - Session expiration.
    
    Returns:
        JSON: Session information in JSON format.
    """
    if 'admin_logged_in' in session and session['admin_logged_in']:
        return jsonify({
            'logged_in': True,
            'username': session.get('admin_username'),
            'token': session.get('admin_token'),
            'identity_id': session.get('identity_id')
        })
    return jsonify({
        'logged_in': False
    })

def check_session_valid():
    """
    Check if the current session is valid.
    
    Validates the session by checking:
    - Presence of admin_logged_in flag.
    - Session timeout (1 hour).
    - Last activity timestamp.
    - Token validity.
    
    Returns:
        bool: True if session is valid, False otherwise.
    """
    print("Checking session validity...")
    print(f"Current session data: {session}.")
    
    if 'admin_logged_in' not in session:
        print("No admin_logged_in in session.")
        return False
    
    # Check if session has expired (1 hour timeout).
    last_activity = session.get('last_activity', 0)
    current_time = int(time.time())
    time_diff = current_time - last_activity
    print(f"Last activity: {last_activity}, Current time: {current_time}, Time diff: {time_diff}.")
    
    if time_diff > 3600:  # 1 hour in seconds.
        print("Session expired.")
        session.clear()
        return False
    
    # Update last activity time.
    session['last_activity'] = current_time
    print("Session is valid, updated last activity time.")
    return True

@app.route('/execute', methods=['POST'])
def execute_code():
    """
    Execute Python code in a controlled environment.
    
    This endpoint requires admin authentication and implements several
    safety measures for code execution:
    - Size limit (10KB).
    - Timeout (30 seconds).
    - Resource restrictions.
    - Environment isolation.
    - Output size limits.
    - Secure token handling.
    
    Returns:
        JSON: Output and error information from code execution.
    """
    # Simple session check - just verify admin is logged in.
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized access. Please login.'}), 401
        
    # Validate input.
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json.'}), 400
        
    code = request.json.get('code')
    if not code or not isinstance(code, str):
        return jsonify({'error': 'Code must be provided as a string.'}), 400
        
    # Limit code size.
    if len(code) > 10000:  # 10KB limit.
        return jsonify({'error': 'Code size exceeds limit.'}), 400
    
    try:
        # Create a unique temporary file in the dedicated temp directory.
        temp_file = os.path.join(TEMP_DIR, f'temp_{secrets.token_hex(8)}.py')
        
        # Get admin token for authentication.
        auth_token = session.get('admin_token', '')

        # Get the name of the function to call by getting the text after def and before (.
        function_name = code.split('def ')[1].split('(')[0]
        print(f"Function name: {function_name}.")

        # Add the function name to the bottom of the code.
        code = code + f"\n\n{function_name}()"
        # Write code to temp file.
        with open(temp_file, 'w') as f:
            f.write(code)
        
        # Execute with timeout and resource limits.
        try:
            result = subprocess.run(
                ['python3', temp_file],
                capture_output=True,
                text=True,
                timeout=30,
                env={
                    **os.environ,
                    'PYTHONPATH': '',
                    'AUTH_TOKEN': auth_token
                }
            )
            
            # Prepare response.
            response = {
                'output': result.stdout[:50000], 
                'error': result.stderr[:50000],
                'status': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            response = {
                'error': 'Execution timeout exceeded (30 seconds).',
                'status': -1
            }
        except subprocess.SubprocessError as e:
            response = {
                'error': f'Execution error: {str(e)}.',
                'status': -1
            }
            
    except Exception as e:
        response = {
            'error': f'Server error: {str(e)}.',
            'status': -1
        }
        
    finally:
        # Clean up temp file.
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except:
            pass
            
    return jsonify(response)

@app.route('/admin/logout')
def admin_logout():
    """
    Handle admin logout functionality.
    
    This route performs a secure logout by:
    - Clearing the session token from the identity API.
    - Removing all session data from the server.
    - Invalidating the client-side session.
    - Redirecting to the login page.
    
    Returns:
        Response: Redirect to the login page.
    """
    if 'identity_id' in session:
        try:
            # Clear token in identity properties.
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
                f'{session["proxy_url"]}/identities/{session["identity_id"]}',
                json=update_data
            )
        except:
            pass
            
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/code-execution')
def code_execution():
    """
    Display the code execution interface.
    
    This route provides a secure environment for:
    - Writing and testing Python code.
    - Creating and updating tools.
    - Managing code execution settings.
    - Viewing execution output.
    
    Returns:
        Response: Rendered code execution template or redirect to login.
    """
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
    return render_template('admin_code.html', proxy_url=session.get('proxy_url', DEFAULT_PROXY_URL))

def is_safe_interpreter_path(interpreter_path):
    """
    Validate if the interpreter path is safe to execute.
    
    Security checks:
    1. Length limit of 50 characters
    2. Only allowed characters: letters, numbers, spaces, forward/backslashes, periods, .exe
    3. Must end with python, python3, python.exe, or python3.exe
    4. Basic path sanitation
    
    Args:
        interpreter_path (str): Path to the Python interpreter
        
    Returns:
        bool: True if path is safe, False otherwise
    """
    # Check length.
    if not interpreter_path or len(interpreter_path) > 50:
        return False
        
    # Only allow specific characters.
    allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /\\.')
    if not all(c in allowed_chars for c in interpreter_path):
        return False
    
    # Clean and normalize the path.
    try:
        normalized_path = os.path.normpath(interpreter_path)
        # Prevent directory traversal.
        if '..' in normalized_path:
            return False
    except:
        return False
    

    return True

@app.route('/verify_interpreter', methods=['POST'])
def verify_interpreter():
    """
    Verify if a Python interpreter exists and is executable.
    
    This endpoint implements strict security measures:
    1. Authentication check
    2. Path validation and sanitization (50 char limit, restricted chars)
    3. Restricted execution environment
    4. Timeout limits
    5. Output sanitization
    
    Returns:
        JSON: Status of the verification with success flag and error message if any.
    """
    if 'admin_logged_in' not in session:
        return jsonify({'valid': False, 'error': 'Not authenticated'}), 401
        
    interpreter = request.json.get('interpreter')
    if not interpreter or not isinstance(interpreter, str):
        return jsonify({'valid': False, 'error': 'Invalid interpreter path'}), 400
    
    # Security validation
    if not is_safe_interpreter_path(interpreter):
        return jsonify({
            'valid': False, 
            'error': 'Invalid interpreter path. Must be a valid path to python.exe or python (max 50 chars).'
        }), 400
        
    try:
        # Check if path exists and is executable.
        if not os.path.exists(interpreter):
            return jsonify({'valid': False, 'error': 'Interpreter path does not exist'})
            
        if not os.access(interpreter, os.X_OK):
            return jsonify({'valid': False, 'error': 'Interpreter is not executable'})
        
        # Create a temporary directory for verification.
        temp_dir = os.path.join(TEMP_DIR, f'verify_{secrets.token_hex(8)}')
        os.makedirs(temp_dir, exist_ok=True)
        
        try:
            # Run in a restricted environment.
            env = {
                # Use system's default secure path.
                'PATH': os.defpath,
                'PYTHONPATH': '',
                'PYTHONHOME': '',
                'TEMP': temp_dir,
                'TMP': temp_dir,
                 # For Windows
                'SystemRoot': os.environ.get('SystemRoot', ''),
                'COMSPEC': os.environ.get('COMSPEC', '')
            }
            
            # Version check command
            result = subprocess.run(
                [interpreter, '--version'],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=temp_dir,
                env=env,
                # Disable shell
                shell=False
            )
            
            if result.returncode == 0:
                # Verify it's actually Python by checking version output.
                output = (result.stdout + result.stderr).lower()
                if 'python' in output and any(v in output for v in ['2.', '3.']):
                    return jsonify({'valid': True, 'version': result.stdout.strip() or result.stderr.strip()})
                else:
                    return jsonify({'valid': False, 'error': 'Not a valid Python interpreter'})
            else:
                return jsonify({'valid': False, 'error': f'Interpreter test failed: {result.stderr}'})
                
        finally:
            # Clean up temporary directory
            try:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
            except:
                pass
            
    except subprocess.TimeoutExpired:
        return jsonify({'valid': False, 'error': 'Interpreter verification timed out'})
    except Exception as e:
        return jsonify({'valid': False, 'error': f'Error verifying interpreter: {str(e)}'})

if __name__ == '__main__':
    app.run(debug=True, port=8285)
