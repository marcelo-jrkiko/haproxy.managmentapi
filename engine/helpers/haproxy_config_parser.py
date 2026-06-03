from __future__ import annotations

from typing import Optional


class HAProxyConfigParser:
    """Parse HAProxy configuration and extract stats endpoint auth details."""

    _SECTION_DIRECTIVES = {
        'global',
        'defaults',
        'frontend',
        'backend',
        'listen',
        'userlist',
        'program',
        'peers',
        'mailers',
    }

    def __init__(self, config_path: str):
        self.config_path = config_path

    def extract_stats_auth(self) -> Optional[dict[str, str]]:
        """Return the first stats auth entry found in a stats listen block."""
        with open(self.config_path, 'r') as config_file:
            lines = config_file.readlines()

        active_listen_name = None
        block_lines: list[str] = []

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue

            tokens = line.split()
            directive = tokens[0].lower()

            if directive == 'listen' and len(tokens) >= 2:
                if active_listen_name is not None:
                    stats_data = self._extract_auth_from_block(active_listen_name, block_lines)
                    if stats_data is not None:
                        return stats_data

                active_listen_name = tokens[1]
                block_lines = []
                continue

            if directive in self._SECTION_DIRECTIVES and directive != 'listen':
                if active_listen_name is not None:
                    stats_data = self._extract_auth_from_block(active_listen_name, block_lines)
                    if stats_data is not None:
                        return stats_data
                active_listen_name = None
                block_lines = []
                continue

            if active_listen_name is not None:
                block_lines.append(line)

        if active_listen_name is not None:
            return self._extract_auth_from_block(active_listen_name, block_lines)

        return None

    def _extract_auth_from_block(
        self, listen_name: str, block_lines: list[str]
    ) -> Optional[dict[str, str]]:
        has_stats_enable = False
        bind_address = None
        stats_uri = None

        for line in block_lines:
            lowered = line.lower()
            if lowered.startswith('stats enable'):
                has_stats_enable = True
            elif lowered.startswith('bind ') and bind_address is None:
                bind_address = line.split(None, 1)[1].strip()
            elif lowered.startswith('stats uri ') and stats_uri is None:
                stats_uri = line.split(None, 2)[2].strip()

        # Support both explicitly named "listen stats" and listen blocks
        # with "stats enable".
        if listen_name.lower() != 'stats' and not has_stats_enable:
            return None

        for line in block_lines:
            lowered = line.lower()
            if not lowered.startswith('stats auth '):
                continue

            auth_value = line.split(None, 2)[2].strip()
            if ':' not in auth_value:
                continue

            username, password = auth_value.split(':', 1)
            return {
                'listen_name': listen_name,
                'bind': bind_address or '',
                'uri': stats_uri or '',
                'username': username,
                'password': password,
            }

        return None