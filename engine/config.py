
import os


class Config:
    def __init__(self):
        self.API_PORT = int(os.getenv('API_PORT', 3000))
        self.API_TOKEN_SECRET = os.getenv('API_TOKEN_SECRET')
        cors_origins = os.getenv('CORS_ORIGINS', '*').strip()
        self.CORS_ORIGINS = '*'
        if cors_origins != '*':
            self.CORS_ORIGINS = [origin.strip() for origin in cors_origins.split(',') if origin.strip()]
        self.CORS_SUPPORTS_CREDENTIALS = os.getenv('CORS_SUPPORTS_CREDENTIALS', 'false').lower() == 'true'
        
        self.DYNAMIC_CONFIG_DIR = os.getenv('DYNAMIC_CONFIG_DIR', './dynamic_config')
        self.SSL_CERT_DIR = os.getenv('SSL_CERT_DIR', './certs')
        self.TEMPLATE_DIR = os.getenv('TEMPLATE_DIR', './templates')
        
        self.START_LOG_REDIRECTOR = os.getenv('START_LOG_REDIRECTOR', 'false').lower() == 'true'
        
        # Path relative paths to absolute paths
        self.DYNAMIC_CONFIG_DIR = os.path.abspath(self.DYNAMIC_CONFIG_DIR)
        self.SSL_CERT_DIR = os.path.abspath(self.SSL_CERT_DIR)
        self.TEMPLATE_DIR = os.path.abspath(self.TEMPLATE_DIR)
        
        self.HAPROXY_CONFIG = os.getenv('HAPROXY_CONFIG', '/usr/local/etc/haproxy/haproxy.cfg')
        self.CERTBUDDY_INTEGRATION_ENABLED = os.getenv('CERTBUDDY_INTEGRATION_ENABLED', 'false').lower() == 'true'
        self.CERTBUDDY = {
            'url': os.getenv('CERTBUDDY_URL', 'https://certbuddy.example.com'),
            'api_key': os.getenv('CERTBUDDY_API_KEY', ''),
        }
        self.RENEW_CERTS_AFTER_DAYS = int(os.getenv('RENEW_CERTS_AFTER_DAYS', 2))
        
        # Ensure dynamic config directory exists
        os.makedirs(self.DYNAMIC_CONFIG_DIR, exist_ok=True)