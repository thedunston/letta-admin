#!/usr/bin/env python3
"""
Task runner for Docker operations.
"""

import os
import sys
import subprocess
from contextlib import contextmanager

# Get the project root directory (where tasks.py is located)
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

def get_docker_compose_cmd():
    """Get the appropriate docker-compose command based on what's available."""
    try:
        # Try docker compose (newer versions)
        subprocess.run(['docker', 'compose', 'version'], capture_output=True, check=True)
        return 'docker compose'
    except subprocess.CalledProcessError:
        try:
            # Try docker-compose (older versions)
            subprocess.run(['docker-compose', 'version'], capture_output=True, check=True)
            return 'docker-compose'
        except subprocess.CalledProcessError:
            print("Error: Neither 'docker compose' nor 'docker-compose' is available.")
            print("Please install Docker and Docker Compose.")
            sys.exit(1)

# Get the docker compose command once at startup
DOCKER_COMPOSE_CMD = get_docker_compose_cmd()

@contextmanager
def cd(path):
    """Change directory context manager."""
    old_dir = os.getcwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(old_dir)

def run_command(cmd):
    """Run a shell command and handle its output."""
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        sys.exit(1)

def get_env_path(env):
    """Get the full path for an environment directory."""
    return os.path.join(PROJECT_ROOT, 'docker', env)

def check_proxy_image():
    """Check if the letta-proxy image exists."""
    try:
        result = subprocess.run(['docker', 'image', 'inspect', 'letta-proxy'], 
                              capture_output=True, 
                              text=True)
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False

def setup_proxy():
    """Clone and build the proxy if not present."""
    if check_proxy_image():
        print("Proxy image already exists.")
        return True

    print("Proxy image not found. Setting up...")
    temp_dir = os.path.join(PROJECT_ROOT, 'tmp')
    proxy_dir = os.path.join(temp_dir, 'letta-pproxy')

    try:
        # Create temp directory if it doesn't exist
        os.makedirs(temp_dir, exist_ok=True)

        # Clone the repository if it doesn't exist
        if not os.path.exists(proxy_dir):
            print("Cloning proxy repository...")
            run_command(f'git clone git@github.com:ahmedrowaihi/letta-pproxy.git {proxy_dir}')

        # Build the proxy image
        print("Building proxy image...")
        with cd(proxy_dir):
            run_command('docker build -t letta-proxy .')

        print("Proxy setup completed successfully.")
        try:
            run_command(f'rm -rf {proxy_dir}')
        except Exception as e:
            print(f"Error listing images: {e}")
        return True

    except Exception as e:
        print(f"Error setting up proxy: {e}")
        return False

def proxy():
    """Run only the proxy service."""
    if not setup_proxy():
        print("Failed to setup proxy. Please check the errors above.")
        return

    env_path = get_env_path('proxy')
    with cd(env_path):
        run_command(f'{DOCKER_COMPOSE_CMD} up')

def full():
    """Run the full application (proxy + admin)."""
    if not setup_proxy():
        print("Failed to setup proxy. Please check the errors above.")
        return

    env_path = get_env_path('full')
    with cd(env_path):
        run_command(f'{DOCKER_COMPOSE_CMD} up')

def dev():
    """Run the development environment."""
    if not setup_proxy():
        print("Failed to setup proxy. Please check the errors above.")
        return

    env_path = get_env_path('dev')
    with cd(env_path):
        run_command(f'{DOCKER_COMPOSE_CMD} up')

def down(env='dev'):
    """Stop all containers for the specified environment."""
    env_path = get_env_path(env)
    if not os.path.exists(env_path):
        print(f"Environment {env} not found. Use: proxy, full, or dev")
        return
    
    with cd(env_path):
        run_command(f'{DOCKER_COMPOSE_CMD} down')

def logs(env='dev', service=None):
    """View logs for the specified environment and service."""
    env_path = get_env_path(env)
    if not os.path.exists(env_path):
        print(f"Environment {env} not found. Use: proxy, full, or dev")
        return
    
    cmd = f'{DOCKER_COMPOSE_CMD} logs'
    if service:
        cmd += f' {service}'
    
    # Check if containers are running
    with cd(env_path):
        result = subprocess.run(f'{DOCKER_COMPOSE_CMD} ps -q', shell=True, capture_output=True, text=True)
        if result.stdout.strip():
            cmd += ' -f'
        run_command(cmd)

def build(env='dev'):
    """Build containers for the specified environment."""
    if not setup_proxy():
        print("Failed to setup proxy. Please check the errors above.")
        return

    env_path = get_env_path(env)
    if not os.path.exists(env_path):
        print(f"Environment {env} not found. Use: proxy, full, or dev")
        return
    
    with cd(env_path):
        run_command(f'{DOCKER_COMPOSE_CMD} build')

def print_help():
    """Print usage help."""
    print("""
Available commands:
    proxy           Run only the proxy service
    full            Run the full application (proxy + admin)
    dev             Run the development environment
    down [env]      Stop containers (env: proxy, full, dev)
    logs [env] [service]  View logs (env: proxy, full, dev)
    build [env]     Build containers (env: proxy, full, dev)
    help            Show this help message
    """)

def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print_help()
        return

    command = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        'proxy': proxy,
        'full': full,
        'dev': dev,
        'down': lambda: down(*args),
        'logs': lambda: logs(*args),
        'build': lambda: build(*args),
        'help': print_help
    }

    if command in commands:
        commands[command]()
    else:
        print(f"Unknown command: {command}")
        print_help()

if __name__ == '__main__':
    main() 