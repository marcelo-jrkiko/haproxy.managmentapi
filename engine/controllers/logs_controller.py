

import logging

from flask import Blueprint, jsonify
from helpers.Utils import UtilHelper
import utils

logs_bp = Blueprint('logs', __name__, url_prefix='/logs')

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
            
            for line in last_lines:
                item = utils.parseAccessLog(line)
                if item:
                    items.append(item)
        
        return {"logs": items}, 200
            
    except Exception as e:
        logging.error(f"Error reading log file: {e}")
        return f'Error reading log file', 500