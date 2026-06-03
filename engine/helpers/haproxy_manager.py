import os
from pathlib import Path

from flask import request

from helpers.Utils import UtilHelper


class HaProxyManager:
    """Encapsulates HAProxy dynamic config file operations with validation and rollback."""

    @staticmethod
    def list_domains():
        app_config = UtilHelper.get_app_config()
        config_entries = []

        for config_file in sorted(Path(app_config.DYNAMIC_CONFIG_DIR).glob('*.cfg')):
            content = config_file.read_text()
            metadata = UtilHelper.extract_config_metadata(content)
            config_entries.append(
                {
                    'domain_id': HaProxyManager.get_domain_id_from_path(str(config_file)),
                    'domain': metadata['domain'],
                    'domains': metadata['domains'],
                    'origin_ip': metadata['origin_ip'],
                    'origin_ips': metadata['origin_ips'],
                }
            )
        return config_entries

    @staticmethod
    def get_config_path(domain_id: str) -> str:
        app_config = UtilHelper.get_app_config()
        return os.path.join(app_config.DYNAMIC_CONFIG_DIR, f'{domain_id}.cfg')

    @staticmethod
    def get_domain_id_from_path(config_path: str) -> str:
        return Path(config_path).stem

    @staticmethod
    def restore_config(config_path: str, previous_content: str | None) -> tuple[bool, str]:
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

    @staticmethod
    def apply_config_file_content(config_path: str, new_content: str) -> tuple[bool, str]:
        previous_content = None
        if os.path.exists(config_path):
            previous_content = Path(config_path).read_text()

        if new_content and not new_content.endswith('\n'):
            new_content = f'{new_content}\n'

        try:
            with open(config_path, 'w') as config_file:
                config_file.write(new_content)
        except Exception as error:
            return False, f'Failed to write config file: {str(error)}'

        valid, validation_message = UtilHelper.validate_haproxy_config()
        if not valid:
            rolled_back, rollback_message = HaProxyManager.restore_config(config_path, previous_content)
            if not rolled_back:
                return (
                    False,
                    f'HAProxy validation failed and rollback failed: {validation_message}. '
                    f'Rollback error: {rollback_message}',
                )
            return False, f'HAProxy validation failed: {validation_message}'

        reloaded, reload_message = UtilHelper.reload_haproxy()
        if not reloaded:
            rolled_back, rollback_message = HaProxyManager.restore_config(config_path, previous_content)
            if not rolled_back:
                return (
                    False,
                    f'HAProxy reload failed and rollback failed: {reload_message}. '
                    f'Rollback error: {rollback_message}',
                )
            return False, f'HAProxy reload failed: {reload_message}'

        return True, 'Config applied successfully.'

    @staticmethod
    def delete_config_file_with_rollback(config_path: str) -> tuple[bool, str]:
        if not os.path.exists(config_path):
            return False, 'Config file not found.'

        previous_content = Path(config_path).read_text()

        try:
            os.remove(config_path)
        except Exception as error:
            return False, f'Failed to delete config file: {str(error)}'

        valid, validation_message = UtilHelper.validate_haproxy_config()
        if not valid:
            rolled_back, rollback_message = HaProxyManager.restore_config(config_path, previous_content)
            if not rolled_back:
                return (
                    False,
                    f'HAProxy validation failed after delete and rollback failed: {validation_message}. '
                    f'Rollback error: {rollback_message}',
                )
            return False, f'HAProxy validation failed after delete: {validation_message}'

        reloaded, reload_message = UtilHelper.reload_haproxy()
        if not reloaded:
            rolled_back, rollback_message = HaProxyManager.restore_config(config_path, previous_content)
            if not rolled_back:
                return (
                    False,
                    f'HAProxy reload failed after delete and rollback failed: {reload_message}. '
                    f'Rollback error: {rollback_message}',
                )
            return False, f'HAProxy reload failed after delete: {reload_message}'

        return True, 'Config deleted successfully.'

    @staticmethod
    def get_config_content_from_request() -> str:
        if request.mimetype == 'multipart/form-data':
            return UtilHelper.get_multipart_value('config_content')

        if request.is_json:
            payload = request.get_json(silent=True) or {}
            return str(payload.get('config_content', '')).strip()

        return request.get_data(as_text=True).strip()