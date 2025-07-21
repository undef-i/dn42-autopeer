import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    FLASK_PORT = int(os.getenv('FLASK_PORT', 5009))
    
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'database.db')
    
    RESEND_API_KEY = os.getenv('RESEND_API_KEY')
    EMAIL_FROM = os.getenv('EMAIL_FROM', 'DN42 AutoPeer <noreply@example.com>')
    
    WIREGUARD_PRIVATE_KEY = os.getenv('WIREGUARD_PRIVATE_KEY')
    WIREGUARD_SERVER_IPV4 = os.getenv('WIREGUARD_SERVER_IPV4')
    WIREGUARD_SERVER_IPV6 = os.getenv('WIREGUARD_SERVER_IPV6')
    WIREGUARD_SERVER_IPV6_LL = os.getenv('WIREGUARD_SERVER_IPV6_LL')
    
    DN42_REGISTRY_URL = os.getenv('DN42_REGISTRY_URL', 'https://git.dn42.dev/dn42/registry.git')
    GIT_USERNAME = os.getenv('GIT_USERNAME')
    GIT_TOKEN = os.getenv('GIT_TOKEN')
    
    ALLOWED_IPS = os.getenv('ALLOWED_IPS', '10.0.0.0/8,172.20.0.0/14,172.31.0.0/16,fd00::/8,fe80::/64')
    
    DEBUG_BYPASS_KEY = os.getenv('DEBUG_BYPASS_KEY')
    
    @classmethod
    def validate_config(cls):
        errors = []
        
        if not cls.RESEND_API_KEY:
            errors.append('RESEND_API_KEY is required')
        
        if not cls.WIREGUARD_PRIVATE_KEY:
            errors.append('WIREGUARD_PRIVATE_KEY is required')
        
        if cls.FLASK_ENV == 'production' and cls.SECRET_KEY == 'dev-secret-key-change-in-production':
            errors.append('SECRET_KEY must be changed in production')
        
        return errors