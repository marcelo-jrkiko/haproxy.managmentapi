import logging
import os
import re
import subprocess
from typing import Any

from flask import current_app, jsonify, request


class UtilHelper:
    """Utility methods shared by config controller routes."""

    @staticmethod
    def extract_config_metadata(config_content: str) -> dict:
        domain_matches = re.findall(r'(?:hdr\(host\)|req_ssl_sni)\s+-i\s+([^\s]+)', config_content)
        origin_ip_matches = re.findall(
            r'^\s*server\s+\S+\s+([^\s:]+)(?::\d+)?(?:\s|$)',
            config_content,
            flags=re.MULTILINE,
        )

        domains = sorted(set(domain_matches))
        origin_ips = sorted(set(origin_ip_matches))

        return {
            'domain': domains[0] if domains else '',
            'domains': domains,
            'origin_ip': origin_ips[0] if origin_ips else '',
            'origin_ips': origin_ips,
        }

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
    def validate_haproxy_config() -> tuple[bool, str]:
        """Validate HAProxy configuration files before reloading."""
        app_config = UtilHelper.get_app_config()
        command = [
            'haproxy',
            '-c',
            '-f',
            app_config.HAPROXY_CONFIG,
            '-f',
            app_config.DYNAMIC_CONFIG_DIR,
        ]

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
        except Exception as error:
            message = f'Failed to run HAProxy validation: {str(error)}'
            logging.error(message)
            return False, message

        output = (result.stdout or result.stderr or '').strip()
        if result.returncode != 0:
            message = output or 'HAProxy validation failed.'
            logging.error(f'HAProxy validation failed: {message}')
            return False, message

        logging.info('HAProxy configuration validated successfully.')
        return True, output or 'Configuration is valid.'

    @staticmethod
    def reload_haproxy() -> tuple[bool, str]:
        """Reload HAProxy to apply new configurations."""
        try:
            result = subprocess.run(
                ['pkill', '-USR2', 'haproxy'],
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode != 0:
                message = (result.stderr or result.stdout or 'Failed to reload HAProxy.').strip()
                logging.error(f'Failed to send HAProxy reload signal: {message}')
                return False, message

            logging.info('HAProxy reload signal sent successfully.')
            return True, 'HAProxy reload signal sent successfully.'
        except Exception as error:
            message = f'Failed to send HAProxy reload signal: {str(error)}'
            logging.error(message)
            return False, message
