

import logging

from flask import Blueprint, jsonify
from helpers.haproxy_config_parser import HAProxyConfigParser
from helpers.Utils import UtilHelper
import utils
import requests

logs_bp = Blueprint('logs', __name__, url_prefix='/logs')

@logs_bp.route('/stats', methods=['GET'])
def get_haproxy_stats():
    HAPROXY_URL = 'http://localhost:9000/haproxy?stats;json'
    
    if not UtilHelper.validate_token():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        parser = HAProxyConfigParser(UtilHelper.get_app_config().HAPROXY_CONFIG)
        authData = parser.extract_stats_auth()
        
        if authData is None:
            logging.error("Stats auth configuration not found in HAProxy config")
            return jsonify({'error': 'Stats auth configuration not found'}), 500
        
        response = requests.get(HAPROXY_URL, auth=(authData['username'], authData['password']), timeout=5)
        response.raise_for_status()
        return jsonify(response.json()), 200
    except Exception as e:
        logging.error(f"Error fetching HAProxy stats: {e}")
        return jsonify({'error': 'Failed to fetch HAProxy stats'}), 500
    

@logs_bp.route('/last', methods=['GET'])
def get_last_logs():
    if not UtilHelper.validate_token():
        return jsonify({'error': 'Unauthorized'}), 401
    
    logFilePath = '/var/log/access.log'
    
    # Get the last 100 lines of the log file
    try:
        items = []
        
        with open(logFilePath, 'r') as log_file:
            lines = log_file.readlines()
            last_lines = lines[-100:]  # Get the last 100 lines
            
            logging.info(f"Read {len(last_lines)} lines from log file for /logs/last endpoint")
            
            for line in last_lines:
                item = utils.parseAccessLog(line)
                if item:
                    items.append(item)
        
        return {"logs": items}, 200
            
    except Exception as e:
        logging.error(f"Error reading log file: {e}")
        return f'Error reading log file', 500