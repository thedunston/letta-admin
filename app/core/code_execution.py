"""
Code execution module for the admin interface.
"""

import os
import secrets
import subprocess
from flask import session
from ..config.settings import TEMP_DIR, CODE_SIZE_LIMIT, EXECUTION_TIMEOUT, MAX_OUTPUT_SIZE

def is_safe_interpreter_path(interpreter_path):
    """
    Validate if the interpreter path is safe to execute.
    
    Args:
        interpreter_path (str): Path to the Python interpreter
        
    Returns:
        bool: True if path is safe, False otherwise
    """
    # Check length
    if not interpreter_path or len(interpreter_path) > 50:
        return False
        
    # Only allow specific characters
    allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /\\.')
    if not all(c in allowed_chars for c in interpreter_path):
        return False
    
    # Clean and normalize the path
    try:
        normalized_path = os.path.normpath(interpreter_path)
        # Prevent directory traversal
        if '..' in normalized_path:
            return False
    except:
        return False

    return True

def execute_code(code):
    """
    Execute Python code in a controlled environment.
    
    Args:
        code (str): Python code to execute
        
    Returns:
        dict: Output and error information from code execution
    """
    if 'admin_logged_in' not in session:
        return {'error': 'Unauthorized access. Please login.', 'status': 401}
        
    if not code or not isinstance(code, str):
        return {'error': 'Code must be provided as a string.', 'status': 400}
        
    # Limit code size
    if len(code) > CODE_SIZE_LIMIT:
        return {'error': 'Code size exceeds limit.', 'status': 400}
    
    try:
        # Create a unique temporary file
        temp_file = os.path.join(TEMP_DIR, f'temp_{secrets.token_hex(8)}.py')
        
        # Get admin token for authentication
        auth_token = session.get('admin_token', '')

        # Get the name of the function to call
        function_name = code.split('def ')[1].split('(')[0]
        
        # Add the function name to the bottom of the code
        code = code + f"\n\n{function_name}()"
        
        # Write code to temp file with proper permissions
        try:
            with open(temp_file, 'w') as f:
                f.write(code)
            os.chmod(temp_file, 0o666)  # Make file readable and writable
        except Exception as e:
            return {'error': f'Failed to create temporary file: {str(e)}.', 'status': 500}
        
        # Execute with timeout and resource limits
        try:
            result = subprocess.run(
                ['python3', temp_file],
                capture_output=True,
                text=True,
                timeout=EXECUTION_TIMEOUT,
                env={
                    **os.environ,
                    'PYTHONPATH': '',
                    'AUTH_TOKEN': auth_token,
                    'TEMP': TEMP_DIR,
                    'TMP': TEMP_DIR
                }
            )
            
            # Prepare response
            response = {
                'output': result.stdout[:MAX_OUTPUT_SIZE], 
                'error': result.stderr[:MAX_OUTPUT_SIZE],
                'status': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            response = {
                'error': f'Execution timeout exceeded ({EXECUTION_TIMEOUT} seconds).',
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
        # Clean up temp file
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except Exception as e:
            print(f"Warning: Could not remove temporary file: {e}")
            
    return response

def verify_interpreter(interpreter):
    """
    Verify if a Python interpreter exists and is executable.
    
    Args:
        interpreter (str): Path to the Python interpreter
        
    Returns:
        dict: Status of the verification with success flag and error message if any
    """
    if 'admin_logged_in' not in session:
        return {'valid': False, 'error': 'Not authenticated', 'status': 401}
        
    if not interpreter or not isinstance(interpreter, str):
        return {'valid': False, 'error': 'Invalid interpreter path', 'status': 400}
    
    # Security validation
    if not is_safe_interpreter_path(interpreter):
        return {
            'valid': False, 
            'error': 'Invalid interpreter path. Must be a valid path to python.exe or python (max 50 chars).',
            'status': 400
        }
        
    try:
        # Check if path exists and is executable
        if not os.path.exists(interpreter):
            return {'valid': False, 'error': 'Interpreter path does not exist', 'status': 400}
            
        if not os.access(interpreter, os.X_OK):
            return {'valid': False, 'error': 'Interpreter is not executable', 'status': 400}
        
        # Create a temporary directory for verification
        temp_dir = os.path.join(TEMP_DIR, f'verify_{secrets.token_hex(8)}')
        try:
            os.makedirs(temp_dir, mode=0o777, exist_ok=True)
        except Exception as e:
            return {'valid': False, 'error': f'Failed to create temporary directory: {str(e)}', 'status': 500}
        
        try:
            # Run in a restricted environment
            env = {
                'PATH': os.defpath,
                'PYTHONPATH': '',
                'PYTHONHOME': '',
                'TEMP': temp_dir,
                'TMP': temp_dir
            }
            
            # Version check command
            result = subprocess.run(
                [interpreter, '--version'],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=temp_dir,
                env=env,
                shell=False
            )
            
            if result.returncode == 0:
                # Verify it's actually Python by checking version output
                output = (result.stdout + result.stderr).lower()
                if 'python' in output and any(v in output for v in ['2.', '3.']):
                    return {'valid': True, 'version': result.stdout.strip() or result.stderr.strip(), 'status': 200}
                else:
                    return {'valid': False, 'error': 'Not a valid Python interpreter', 'status': 400}
            else:
                return {'valid': False, 'error': f'Interpreter test failed: {result.stderr}', 'status': 400}
                
        finally:
            # Clean up temporary directory
            try:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as e:
                print(f"Warning: Could not remove temporary directory: {e}")
            
    except subprocess.TimeoutExpired:
        return {'valid': False, 'error': 'Interpreter verification timed out', 'status': 400}
    except Exception as e:
        return {'valid': False, 'error': f'Error verifying interpreter: {str(e)}', 'status': 500} 