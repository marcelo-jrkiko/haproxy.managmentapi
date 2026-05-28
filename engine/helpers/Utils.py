import logging
import os
import re
from typing import Any

from flask import current_app, jsonify, request


class UtilHelper:
    """Utility methods shared by config controller routes."""


    @staticmethod
    def require_multipart_form():
        """Ensure request payload is multipart/form-data."""
        if request.mimetype != 'multipart/form-data':
            return jsonify({'error': 'Content-Type must be multipart/form-data'}), 400
        return None

    @staticmethod
    def get_multipart_value(field_name):
        """Read a field value from multipart text part or uploaded file."""
        form_value = request.form.get(field_name)
        if form_value is not None:
            return form_value.strip()

        uploaded_file = request.files.get(field_name)
        if uploaded_file:
            return uploaded_file.read().decode('utf-8').strip()

        return ''

    @staticmethod
    def get_app_config() -> Any:
        return current_app.config['APP_CONFIG']

    @staticmethod
    def generate_domain_id(domain: str) -> str:
        """Generate a sanitized domain ID from domain name."""
        sanitized = re.sub(r'[^a-zA-Z0-9]', '_', domain)
        sanitized = re.sub(r'_+', '_', sanitized).strip('_')
        return sanitized.lower()

    @staticmethod
    def validate_token() -> bool:
        """Validate API token from request headers."""
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        app_config = UtilHelper.get_app_config()
        return bool(token and token == app_config.API_TOKEN_SECRET)

    @staticmethod
    def reload_haproxy() -> None:
        """Reload HAProxy to apply new configurations."""
        try:
            os.system('pkill -USR2 haproxy')
            logging.info('HAProxy reload signal sent successfully.')
        except Exception as error:
            logging.error(f'Failed to send HAProxy reload signal: {str(error)}')
