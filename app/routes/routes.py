"""
Routes module for the admin interface.
"""

from flask import render_template, request, jsonify, redirect, url_for, session
from ..auth.auth import login, logout, check_session_valid
from ..core.code_execution import execute_code, verify_interpreter
from ..core.proxy import test_proxy_connection, proxy_request
from ..config.settings import DEFAULT_PROXY_URL
from ..utils.session import get_proxy_url
from ..utils.decorators import require_login, require_json, with_proxy_url

def register_routes(app):
    """
    Register all routes for the Flask application.
    
    Args:
        app: Flask application instance
    """
    @app.route('/health')
    def health():
        """Health check endpoint."""
        return jsonify({'status': 'ok'}), 200

    @app.route('/')
    def index():
        """Render the admin index page."""
        return render_template('admin/index.html')

    @app.route('/test-proxy', methods=['POST'])
    @require_json
    def test_proxy():
        """Test the connection to the proxy server."""
        proxy_url = request.json.get('proxy_url', '').rstrip('/')
        result = test_proxy_connection(proxy_url)
        return jsonify(result), result.get('status', 500)

    @app.route('/login', methods=['GET', 'POST'])
    def admin_login():
        """Handle admin login functionality."""
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            proxy_url = request.form.get('proxy_url', DEFAULT_PROXY_URL)
            
            success, message, redirect_url = login(username, password, proxy_url)
            if success:
                return redirect(redirect_url)
            return render_template('admin/login.html', error=message, default_proxy_url=DEFAULT_PROXY_URL)
        
        return render_template('admin/login.html', default_proxy_url=DEFAULT_PROXY_URL)

    @app.route('/admin/dashboard')
    @require_login
    @with_proxy_url
    def admin_dashboard(proxy_url):
        """Display the admin dashboard."""
        return render_template('admin/dashboard.html', proxy_url=proxy_url)

    @app.route('/admin/session-info')
    def session_info():
        """Provide session information for the frontend."""
        if check_session_valid():
            return jsonify({
                'logged_in': True,
                'username': session.get('admin_username'),
                'token': session.get('admin_token'),
                'identity_id': session.get('identity_id')
            })
        return jsonify({'logged_in': False})

    @app.route('/execute', methods=['POST'])
    @require_login
    @require_json
    def execute():
        """Execute Python code in a controlled environment."""
        code = request.json.get('code')
        result = execute_code(code)
        return jsonify(result), result.get('status', 500)

    @app.route('/verify_interpreter', methods=['POST'])
    @require_json
    def verify():
        """Verify if a Python interpreter exists and is executable."""
        interpreter = request.json.get('interpreter')
        result = verify_interpreter(interpreter)
        return jsonify(result), result.get('status', 500)

    @app.route('/admin/logout')
    def admin_logout():
        """Handle admin logout functionality."""
        success, message, redirect_url = logout()
        return redirect(redirect_url)

    @app.route('/code-execution')
    @require_login
    @with_proxy_url
    def code_execution(proxy_url):
        """Display the code execution interface."""
        return render_template('admin/code.html', proxy_url=proxy_url)

    @app.route('/proxy/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
    @require_login
    def proxy(path):
        """Forward requests to the proxy server."""
        result = proxy_request(path)
        if isinstance(result, dict):
            return jsonify(result), result.get('status', 500)
        return result 