"""
Proxy module for handling API requests.
"""

import requests
from flask import request, Response, session
from ..config.settings import DEFAULT_PROXY_URL
from ..utils.session import get_proxy_url

def test_proxy_connection(proxy_url):
    """
    Test the connection to the proxy server.
    
    Args:
        proxy_url (str): URL of the proxy server
        
    Returns:
        dict: Status of the connection test with success flag and message
    """
    proxy_url = proxy_url.rstrip('/')
    if not proxy_url:
        return {'error': 'Proxy URL is required.', 'status': 400}
        
    try:
        response = requests.get(f'{proxy_url}/health')
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'ok':
                return {
                    'success': True,
                    'message': f'Successfully connected to proxy. Version: {data.get("version", "unknown")}.',
                    'status': 200
                }
        return {
            'success': False,
            'message': 'Invalid response from proxy server.',
            'status': 400
        }
    except requests.exceptions.RequestException as e:
        return {
            'success': False,
            'message': f'Failed to connect to proxy: {str(e)}.',
            'status': 500
        }

def proxy_request(path):
    """
    Forward requests to the proxy server.
    
    Args:
        path (str): The path to forward to the proxy server
        
    Returns:
        Response: The proxy server's response
    """
    if 'admin_logged_in' not in session:
        return {'error': 'Unauthorized', 'status': 401}
        
    proxy_url = get_proxy_url()
    target_url = f'{proxy_url}/{path}'
    
    # Forward the request method and body
    method = request.method
    headers = {key: value for key, value in request.headers if key.lower() not in ['host', 'content-length']}
    data = request.get_data() if request.get_data() else None
    
    try:
        response = requests.request(
            method=method,
            url=target_url,
            headers=headers,
            data=data,
            stream=True
        )
        
        # Stream the response back to the client
        return Response(
            response.iter_content(chunk_size=8192),
            status=response.status_code,
            headers=dict(response.headers)
        )
    except requests.exceptions.RequestException as e:
        return {'error': f'Proxy request failed: {str(e)}', 'status': 500} 