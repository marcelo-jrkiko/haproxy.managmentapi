
import os


class Config:
    def __init__(self):
        self.API_PORT = int(os.getenv('API_PORT', 3000))
        self.API_TOKEN_SECRET = os.getenv('API_TOKEN_SECRET')
        
        self.DYNAMIC_CONFIG_DIR = os.getenv('DYNAMIC_CONFIG_DIR', './dynamic_config')
        self.SSL_CERT_DIR = os.getenv('SSL_CERT_DIR', './certs')
        self.TEMPLATE_DIR = os.getenv('TEMPLATE_DIR', './templates')
        
        self.START_LOG_REDIRECTOR = os.getenv('START_LOG_REDIRECTOR', 'false').lower() == 'true'
        
        # Path relative paths to absolute paths
        self.DYNAMIC_CONFIG_DIR = os.path.abspath(self.DYNAMIC_CONFIG_DIR)
        self.SSL_CERT_DIR = os.path.abspath(self.SSL_CERT_DIR)
        self.TEMPLATE_DIR = os.path.abspath(self.TEMPLATE_DIR)
        
        
        # Ensure dynamic config directory exists
        os.makedirs(self.DYNAMIC_CONFIG_DIR, exist_ok=True)