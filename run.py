#!/usr/bin/env python3

import sys
import os
from pathlib import Path

def check_requirements():
    try:
        import flask
        import resend
        import paramiko
        import gnupg
        from dotenv import load_dotenv
    except ImportError as e:
        print(f"Missing required package: {e}")
        print("Please run: pip install -r requirements.txt")
        return False
    return True

def check_config():
    env_file = Path('.env')
    if not env_file.exists():
        print("Configuration file .env not found!")
        print("Please copy .env.example to .env and configure it.")
        return False
    return True

def main():
    print("DN42 AutoPeer - Starting...")
    
    if not check_requirements():
        sys.exit(1)
    
    if not check_config():
        sys.exit(1)
    
    try:
        from app.main import app
        from config import Config
        
        config_errors = Config.validate_config()
        if config_errors:
            print("Configuration errors:")
            for error in config_errors:
                print(f"  - {error}")
            sys.exit(1)
        
        print(f"Starting server on port {Config.FLASK_PORT}")
        print(f"Access the web interface at: http://localhost:{Config.FLASK_PORT}")
        
        app.run(
            debug=Config.FLASK_DEBUG,
            port=Config.FLASK_PORT,
            host='0.0.0.0'
        )
        
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()