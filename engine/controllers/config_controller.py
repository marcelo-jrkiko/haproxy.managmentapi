import logging
import os
import re
from pathlib import Path

from flask import Blueprint, jsonify, request

from helpers.Utils import UtilHelper

config_blueprint = Blueprint('config_controller', __name__)

@config_blueprint.route('/config', methods=['POST'])
def create_config():
    """Create a new HAProxy config file for a domain."""
    if not UtilHelper.validate_token():
        return jsonify({'error': 'Unauthorized'}), 401

    multipart_error = UtilHelper.require_multipart_form()
    if multipart_error:
        return multipart_error

    domain = UtilHelper.get_multipart_value('domain')
    origin_ip = UtilHelper.get_multipart_value('origin_ip')
    template_id = UtilHelper.get_multipart_value('template_id') or 'default'

    if not domain or not origin_ip:
        return jsonify({'error': 'Missing required fields: domain, origin_ip'}), 400

    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', origin_ip):
        return jsonify({'error': 'Invalid origin_ip format'}), 400

    app_config = UtilHelper.get_app_config()
    template_path = os.path.join(app_config.TEMPLATE_DIR, f'{template_id}.cfg')
    if not os.path.exists(template_path):
        logging.error(f'Config template not found: {template_path}')
        return jsonify({'error': f'Config template not found: {template_id}'}), 400

    config_template = Path(template_path).read_text()

    domain_id = UtilHelper.generate_domain_id(domain)
    config_filename = f'{domain_id}.cfg'
    config_path = os.path.join(app_config.DYNAMIC_CONFIG_DIR, config_filename)

    config_content = config_template.replace('${DOMAIN_ID}', domain_id)
    config_content = config_content.replace('${DOMAIN}', domain)
    config_content = config_content.replace('${ORIGIN_IP}', origin_ip)

    ssl_cert_path = os.path.join(app_config.SSL_CERT_DIR, f'{domain}.pem')
    ssl_cert = UtilHelper.get_multipart_value('ssl_cert')
    ssl_key = UtilHelper.get_multipart_value('ssl_key')

    if ssl_cert and ssl_key:
        try:
            with open(ssl_cert_path, 'w') as cert_file:
                cert_file.write(ssl_cert)
                cert_file.write('\n')
                cert_file.write(ssl_key)
            logging.info(f'SSL certificate saved for domain {domain}')
        except Exception as e:
            return jsonify({'error': f'Failed to save SSL certificate: {str(e)}'}), 500
    else:
        ssl_cert_path = os.path.join(app_config.SSL_CERT_DIR, 'default.pem')
        logging.warning(
            f'No SSL certificate provided for domain {domain}. Using default certificate.'
        )

    config_content = config_content.replace('${SSL_CERT_PATH}', ssl_cert_path)

    try:
        with open(config_path, 'w') as config_file:
            config_file.write(config_content)

        UtilHelper.reload_haproxy()

        return jsonify(
            {
                'status': 'success',
                'message': f'Config created for domain {domain}',
                'domain_id': domain_id,
            }
        ), 201
    except Exception as e:
        return jsonify({'error': f'Failed to write config file: {str(e)}'}), 500


@config_blueprint.route('/config/<domain>', methods=['DELETE'])
def delete_config(domain):
    """Delete HAProxy config file for a domain."""
    if not UtilHelper.validate_token():
        return jsonify({'error': 'Unauthorized'}), 401

    domain = domain.strip()
    if not domain:
        return jsonify({'error': 'Domain parameter cannot be empty'}), 400

    app_config = UtilHelper.get_app_config()
    domain_id = UtilHelper.generate_domain_id(domain)
    config_filename = f'{domain_id}.cfg'
    config_path = os.path.join(app_config.DYNAMIC_CONFIG_DIR, config_filename)

    if not os.path.exists(config_path):
        return jsonify({'error': f'Config file not found for domain {domain}'}), 404

    try:
        os.remove(config_path)

        UtilHelper.reload_haproxy()

        return jsonify(
            {
                'status': 'success',
                'message': f'Config deleted for domain {domain}',
                'domain_id': domain_id,
            }
        ), 200
    except Exception as e:
        return jsonify({'error': f'Failed to delete config file: {str(e)}'}), 500


@config_blueprint.route('/config/<domain>/certificate', methods=['PUT'])
def update_certificate(domain):
    """Update SSL certificate pair for a domain and reload HAProxy."""
    if not UtilHelper.validate_token():
        return jsonify({'error': 'Unauthorized'}), 401

    domain = domain.strip()
    if not domain:
        return jsonify({'error': 'Domain parameter cannot be empty'}), 400

    multipart_error = UtilHelper.require_multipart_form()
    if multipart_error:
        return multipart_error

    ssl_cert = UtilHelper.get_multipart_value('ssl_cert')
    ssl_key = UtilHelper.get_multipart_value('ssl_key')
    if not ssl_cert or not ssl_key:
        return jsonify({'error': 'Missing required fields: ssl_cert, ssl_key'}), 400

    app_config = UtilHelper.get_app_config()
    domain_id = UtilHelper.generate_domain_id(domain)
    config_filename = f'{domain_id}.cfg'
    config_path = os.path.join(app_config.DYNAMIC_CONFIG_DIR, config_filename)

    if not os.path.exists(config_path):
        return jsonify({'error': f'Config file not found for domain {domain}'}), 404

    ssl_cert_path = os.path.join(app_config.SSL_CERT_DIR, f'{domain}.pem')
    try:
        with open(ssl_cert_path, 'w') as cert_file:
            cert_file.write(ssl_cert)
            cert_file.write('\n')
            cert_file.write(ssl_key)

        UtilHelper.reload_haproxy()

        return jsonify(
            {
                'status': 'success',
                'message': f'Certificate updated for domain {domain}',
                'domain_id': domain_id,
            }
        ), 200
    except Exception as e:
        return jsonify({'error': f'Failed to update certificate: {str(e)}'}), 500


@config_blueprint.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'ok'}), 200
