"""
Main entry point for the admin interface.
"""

import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        debug=os.environ.get('ADMIN_INTERFACE_DEBUG', True),
        port=8285
    ) 