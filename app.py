import os
import re
from pathlib import Path
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import logging

logging.basicConfig(level=logging.INFO)

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
API_PORT = int(os.getenv('API_PORT', 3000))
API_TOKEN_SECRET = os.getenv('API_TOKEN_SECRET')
DYNAMIC_CONFIG_DIR = os.getenv('DYNAMIC_CONFIG_DIR', './dynamic_config')

# Ensure dynamic config directory exists
Path(DYNAMIC_CONFIG_DIR).mkdir(parents=True, exist_ok=True)

# Load template
TEMPLATE_PATH = 'domain_config.template'
with open(TEMPLATE_PATH, 'r') as f:
    CONFIG_TEMPLATE = f.read()


def generate_domain_id(domain: str) -> str:
    """Generate a sanitized domain ID from domain name."""
    # Replace dots and hyphens with underscores, remove other special chars
    sanitized = re.sub(r'[^a-zA-Z0-9]', '_', domain)
    # Remove leading/trailing underscores and multiple consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized).strip('_')
    return sanitized.lower()


def validate_token():
    """Validate API token from request headers."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token or token != API_TOKEN_SECRET:
        return False
    return True

def reload_haproxy():
    """Reload HAProxy to apply new configurations."""
    # Reload HAPROXY using signal
    try:
        # Signal HAProxy process to reload gracefully
        os.system('pkill -USR2 haproxy')
        logging.info("HAProxy reload signal sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send HAProxy reload signal: {str(e)}")
        

@app.route('/config', methods=['POST'])
def create_config():
    """
    Create a new HAProxy config file for a domain.
    
    Request body:
    {
        "domain": "example.com",
        "origin_ip": "192.168.1.100"
    }
    """
    if not validate_token():
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    domain = data.get('domain', '').strip()
    origin_ip = data.get('origin_ip', '').strip()
    
    if not domain or not origin_ip:
        return jsonify({'error': 'Missing required fields: domain, origin_ip'}), 400
    
    # Validate IP address format (basic validation)
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', origin_ip):
        return jsonify({'error': 'Invalid origin_ip format'}), 400
    
    domain_id = generate_domain_id(domain)
    config_filename = f"{domain_id}.cfg"
    config_path = os.path.join(DYNAMIC_CONFIG_DIR, config_filename)
    
    # Generate config from template
    config_content = CONFIG_TEMPLATE.replace('${DOMAIND_ID}', domain_id)
    config_content = config_content.replace('${DOMAIN}', domain)
    config_content = config_content.replace('${ORIGIN_IP}', origin_ip)
    
    # Write config file
    try:
        with open(config_path, 'w') as f:
            f.write(config_content)
            
        reload_haproxy()
        
        return jsonify({
            'status': 'success',
            'message': f'Config created for domain {domain}',
            'domain_id': domain_id,
        }), 201
    except Exception as e:
        return jsonify({'error': f'Failed to write config file: {str(e)}'}), 500


@app.route('/config/<domain>', methods=['DELETE'])
def delete_config(domain):
    """
    Delete HAProxy config file for a domain.
    
    URL parameter: domain (e.g., /config/example.com)
    """
    if not validate_token():
        return jsonify({'error': 'Unauthorized'}), 401
    
    domain = domain.strip()
    if not domain:
        return jsonify({'error': 'Domain parameter cannot be empty'}), 400
    
    domain_id = generate_domain_id(domain)
    config_filename = f"{domain_id}.cfg"
    config_path = os.path.join(DYNAMIC_CONFIG_DIR, config_filename)
    
    if not os.path.exists(config_path):
        return jsonify({'error': f'Config file not found for domain {domain}'}), 404
    
    try:
        os.remove(config_path)
        
        reload_haproxy()
        
        return jsonify({
            'status': 'success',
            'message': f'Config deleted for domain {domain}',
            'domain_id': domain_id
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to delete config file: {str(e)}'}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'ok'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=API_PORT, debug=False)
