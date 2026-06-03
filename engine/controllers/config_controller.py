import logging
import os
import re
from pathlib import Path

from flask import Blueprint, jsonify, request

from helpers.Utils import UtilHelper

config_blueprint = Blueprint('config_controller', __name__)


def _require_auth():
    if not UtilHelper.validate_token():
        return jsonify({'error': 'Unauthorized'}), 401
    return None


def _get_config_path(domain_id: str) -> str:
    app_config = UtilHelper.get_app_config()
    return os.path.join(app_config.DYNAMIC_CONFIG_DIR, f'{domain_id}.cfg')


def _get_domain_id_from_path(config_path: str) -> str:
    return Path(config_path).stem


def _extract_config_metadata(config_content: str) -> dict:
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


def _restore_config(config_path: str, previous_content: str | None) -> tuple[bool, str]:
    try:
        if previous_content is None:
            if os.path.exists(config_path):
                os.remove(config_path)
        else:
            with open(config_path, 'w') as config_file:
                config_file.write(previous_content)
    except Exception as error:
        return False, f'Failed to restore previous config file: {str(error)}'

    valid, validation_message = UtilHelper.validate_haproxy_config()
    if not valid:
        return False, validation_message

    reloaded, reload_message = UtilHelper.reload_haproxy()
    if not reloaded:
        return False, reload_message

    return True, 'Rollback completed successfully.'


def _apply_config_file_content(config_path: str, new_content: str) -> tuple[bool, str]:
    previous_content = None
    if os.path.exists(config_path):
        previous_content = Path(config_path).read_text()

    try:
        with open(config_path, 'w') as config_file:
            config_file.write(new_content)
    except Exception as error:
        return False, f'Failed to write config file: {str(error)}'

    valid, validation_message = UtilHelper.validate_haproxy_config()
    if not valid:
        rolled_back, rollback_message = _restore_config(config_path, previous_content)
        if not rolled_back:
            return (
                False,
                f'HAProxy validation failed and rollback failed: {validation_message}. '
                f'Rollback error: {rollback_message}',
            )
        return False, f'HAProxy validation failed: {validation_message}'

    reloaded, reload_message = UtilHelper.reload_haproxy()
    if not reloaded:
        rolled_back, rollback_message = _restore_config(config_path, previous_content)
        if not rolled_back:
            return (
                False,
                f'HAProxy reload failed and rollback failed: {reload_message}. '
                f'Rollback error: {rollback_message}',
            )
        return False, f'HAProxy reload failed: {reload_message}'

    return True, 'Config applied successfully.'


def _delete_config_file_with_rollback(config_path: str) -> tuple[bool, str]:
    if not os.path.exists(config_path):
        return False, 'Config file not found.'

    previous_content = Path(config_path).read_text()

    try:
        os.remove(config_path)
    except Exception as error:
        return False, f'Failed to delete config file: {str(error)}'

    valid, validation_message = UtilHelper.validate_haproxy_config()
    if not valid:
        rolled_back, rollback_message = _restore_config(config_path, previous_content)
        if not rolled_back:
            return (
                False,
                f'HAProxy validation failed after delete and rollback failed: {validation_message}. '
                f'Rollback error: {rollback_message}',
            )
        return False, f'HAProxy validation failed after delete: {validation_message}'

    reloaded, reload_message = UtilHelper.reload_haproxy()
    if not reloaded:
        rolled_back, rollback_message = _restore_config(config_path, previous_content)
        if not rolled_back:
            return (
                False,
                f'HAProxy reload failed after delete and rollback failed: {reload_message}. '
                f'Rollback error: {rollback_message}',
            )
        return False, f'HAProxy reload failed after delete: {reload_message}'

    return True, 'Config deleted successfully.'


def _get_config_content_from_request() -> str:
    if request.mimetype == 'multipart/form-data':
        return UtilHelper.get_multipart_value('config_content')

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        return str(payload.get('config_content', '')).strip()

    return request.get_data(as_text=True).strip()

@config_blueprint.route('/config', methods=['POST'])
def create_config():
    """Create a new HAProxy config file for a domain."""
    auth_error = _require_auth()
    if auth_error:
        return auth_error

    multipart_error = UtilHelper.require_multipart_form()
    if multipart_error:
        return multipart_error

    domain = UtilHelper.get_multipart_value('domain')
    origin_ip = UtilHelper.get_multipart_value('origin_ip')
    template_id = UtilHelper.get_multipart_value('template_id') or 'default'

    if not domain or not origin_ip:
        logging.error('Missing required fields: domain, origin_ip')
        return jsonify({'error': 'Missing required fields: domain, origin_ip'}), 400

    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', origin_ip):
        logging.error(f'Invalid origin_ip format: {origin_ip}')
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
            logging.error(f'Failed to save SSL certificate for domain {domain}: {str(e)}')
            return jsonify({'error': f'Failed to save SSL certificate: {str(e)}'}), 500
    else:
        ssl_cert_path = os.path.join(app_config.SSL_CERT_DIR, 'default.pem')
        logging.warning(
            f'No SSL certificate provided for domain {domain}. Using default certificate.'
        )

    config_content = config_content.replace('${SSL_CERT_PATH}', ssl_cert_path)

    applied, message = _apply_config_file_content(config_path, config_content)
    if not applied:
        return jsonify({'error': message}), 500

    return jsonify(
        {
            'status': 'success',
            'message': f'Config created for domain {domain}',
            'domain_id': domain_id,
        }
    ), 201


@config_blueprint.route('/config/<domain>', methods=['DELETE'])
def delete_config(domain):
    """Delete HAProxy config file for a domain."""
    auth_error = _require_auth()
    if auth_error:
        return auth_error

    domain = domain.strip()
    if not domain:
        return jsonify({'error': 'Domain parameter cannot be empty'}), 400

    domain_id = UtilHelper.generate_domain_id(domain)
    config_path = _get_config_path(domain_id)

    if not os.path.exists(config_path):
        return jsonify({'error': f'Config file not found for domain {domain}'}), 404

    deleted, message = _delete_config_file_with_rollback(config_path)
    if not deleted:
        return jsonify({'error': message}), 500

    return jsonify(
        {
            'status': 'success',
            'message': f'Config deleted for domain {domain}',
            'domain_id': domain_id,
        }
    ), 200


@config_blueprint.route('/config/<domain>/certificate', methods=['PUT'])
def update_certificate(domain):
    """Update SSL certificate pair for a domain and reload HAProxy."""
    auth_error = _require_auth()
    if auth_error:
        return auth_error

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
    config_path = _get_config_path(domain_id)

    if not os.path.exists(config_path):
        return jsonify({'error': f'Config file not found for domain {domain}'}), 404

    ssl_cert_path = os.path.join(app_config.SSL_CERT_DIR, f'{domain}.pem')
    try:
        with open(ssl_cert_path, 'w') as cert_file:
            cert_file.write(ssl_cert)
            cert_file.write('\n')
            cert_file.write(ssl_key)

        valid, validation_message = UtilHelper.validate_haproxy_config()
        if not valid:
            return jsonify({'error': f'HAProxy validation failed: {validation_message}'}), 400

        reloaded, reload_message = UtilHelper.reload_haproxy()
        if not reloaded:
            return jsonify({'error': f'HAProxy reload failed: {reload_message}'}), 500

        return jsonify(
            {
                'status': 'success',
                'message': f'Certificate updated for domain {domain}',
                'domain_id': domain_id,
            }
        ), 200
    except Exception as e:
        return jsonify({'error': f'Failed to update certificate: {str(e)}'}), 500


@config_blueprint.route('/configs', methods=['GET'])
def list_configs_by_domain_id():
    """List configured files with domain IDs, domains and origin IPs."""
    auth_error = _require_auth()
    if auth_error:
        return auth_error

    app_config = UtilHelper.get_app_config()
    config_entries = []

    for config_file in sorted(Path(app_config.DYNAMIC_CONFIG_DIR).glob('*.cfg')):
        content = config_file.read_text()
        metadata = _extract_config_metadata(content)
        config_entries.append(
            {
                'domain_id': _get_domain_id_from_path(str(config_file)),
                'domain': metadata['domain'],
                'domains': metadata['domains'],
                'origin_ip': metadata['origin_ip'],
                'origin_ips': metadata['origin_ips'],
            }
        )

    return jsonify({'total': len(config_entries), 'configs': config_entries}), 200


@config_blueprint.route('/configs/<domain_id>', methods=['DELETE'])
def delete_config_by_domain_id(domain_id):
    """Delete HAProxy config file using DOMAIN_ID."""
    auth_error = _require_auth()
    if auth_error:
        return auth_error

    domain_id = domain_id.strip().lower()
    if not domain_id:
        return jsonify({'error': 'DOMAIN_ID parameter cannot be empty'}), 400

    config_path = _get_config_path(domain_id)
    if not os.path.exists(config_path):
        return jsonify({'error': f'Config file not found for DOMAIN_ID {domain_id}'}), 404

    deleted, message = _delete_config_file_with_rollback(config_path)
    if not deleted:
        return jsonify({'error': message}), 500

    return jsonify({'status': 'success', 'message': message, 'domain_id': domain_id}), 200


@config_blueprint.route('/configs/<domain_id>', methods=['PUT'])
def update_config_by_domain_id(domain_id):
    """Update config content for DOMAIN_ID with validate+rollback safety."""
    auth_error = _require_auth()
    if auth_error:
        return auth_error

    domain_id = domain_id.strip().lower()
    if not domain_id:
        return jsonify({'error': 'DOMAIN_ID parameter cannot be empty'}), 400

    config_path = _get_config_path(domain_id)
    if not os.path.exists(config_path):
        return jsonify({'error': f'Config file not found for DOMAIN_ID {domain_id}'}), 404

    config_content = _get_config_content_from_request()
    if not config_content:
        return jsonify({'error': 'Missing required field: config_content'}), 400

    applied, message = _apply_config_file_content(config_path, config_content)
    if not applied:
        return jsonify({'error': message}), 500

    metadata = _extract_config_metadata(config_content)
    return jsonify(
        {
            'status': 'success',
            'message': 'Configuration updated successfully.',
            'domain_id': domain_id,
            'domain': metadata['domain'],
            'origin_ips': metadata['origin_ips'],
        }
    ), 200


@config_blueprint.route('/configs/<domain_id>', methods=['GET'])
def get_config_by_domain_id(domain_id):
    """Fetch raw config content by DOMAIN_ID."""
    auth_error = _require_auth()
    if auth_error:
        return auth_error

    domain_id = domain_id.strip().lower()
    if not domain_id:
        return jsonify({'error': 'DOMAIN_ID parameter cannot be empty'}), 400

    config_path = _get_config_path(domain_id)
    if not os.path.exists(config_path):
        return jsonify({'error': f'Config file not found for DOMAIN_ID {domain_id}'}), 404

    content = Path(config_path).read_text()
    metadata = _extract_config_metadata(content)
    return jsonify(
        {
            'domain_id': domain_id,
            'domain': metadata['domain'],
            'origin_ips': metadata['origin_ips'],
            'content': content,
        }
    ), 200


@config_blueprint.route('/configs/reload', methods=['POST'])
def validate_and_reload_configs():
    """Validate all loaded HAProxy config and refresh process."""
    auth_error = _require_auth()
    if auth_error:
        return auth_error

    valid, validation_message = UtilHelper.validate_haproxy_config()
    if not valid:
        return jsonify({'error': f'HAProxy validation failed: {validation_message}'}), 400

    reloaded, reload_message = UtilHelper.reload_haproxy()
    if not reloaded:
        return jsonify({'error': f'HAProxy reload failed: {reload_message}'}), 500

    return jsonify(
        {
            'status': 'success',
            'message': 'HAProxy configuration validated and reloaded.',
            'validation_output': validation_message,
        }
    ), 200
