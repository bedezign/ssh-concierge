"""1Password op CLI wrapper for SSH config items."""

from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from typing import Any

from ssh_concierge.expand import expand_braces
from ssh_concierge.models import HostConfig

# Fields from the "SSH Config" section that map to HostConfig attributes directly
_KNOWN_FIELDS = {'aliases', 'hostname', 'port', 'user', 'password'}

SSH_CONFIG_SECTION_PREFIX = 'SSH Config'
SSH_HOST_TAG = 'SSH Host'


class OpError(Exception):
    """Raised when an op CLI command fails."""


def _run_op(args: list[str], timeout: int = 120) -> str:
    """Run an op CLI command and return stdout."""
    try:
        result = subprocess.run(
            ['op', *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise OpError('op CLI not found — is 1Password CLI installed?') from exc
    except subprocess.TimeoutExpired as exc:
        raise OpError(f'op command timed out after {timeout}s') from exc

    if result.returncode != 0:
        raise OpError(f'op failed (exit {result.returncode}): {result.stderr.strip()}')

    return result.stdout


def _is_managed(item: dict[str, Any]) -> bool:
    """Check if an item should be managed by ssh-concierge.

    An item is managed if it's an SSH Key (any) or has the 'SSH Host' tag.
    The 'SSH Config' section check happens later during parsing.
    """
    if item.get('category') == 'SSH_KEY':
        return True
    tags = [t.get('name', t) if isinstance(t, dict) else t for t in item.get('tags', [])]
    return SSH_HOST_TAG in tags


def list_managed_item_ids() -> list[str]:
    """List IDs of all managed items (SSH Keys + SSH Host tagged)."""
    output = _run_op([
        'item', 'list',
        '--format', 'json',
    ])
    items = json.loads(output)
    return [item['id'] for item in items if _is_managed(item)]


def get_item(item_id: str) -> dict[str, Any]:
    """Fetch full item details by ID."""
    output = _run_op(['item', 'get', item_id, '--format', 'json'])
    return json.loads(output)


def parse_item_to_host_configs(item: dict[str, Any]) -> list[HostConfig]:
    """Parse a 1Password item into HostConfigs.

    Supports multiple sections per item: any section whose label starts with
    "SSH Config" produces a HostConfig. All share the item's public key and
    fingerprint.

    Returns empty list if no SSH Config sections found.
    """
    fields = item.get('fields', [])

    # Extract public key + fingerprint from item-level fields
    public_key = None
    fingerprint = None
    for field in fields:
        if field.get('section'):
            continue
        if field.get('label') == 'public key':
            public_key = field.get('value')
        elif field.get('label') == 'fingerprint':
            fingerprint = field.get('value')

    # Group fields by section (only SSH Config* sections)
    sections: dict[str, dict[str, str]] = defaultdict(dict)
    for field in fields:
        section = field.get('section')
        if not section:
            continue
        label = section.get('label', '')
        if not label.startswith(SSH_CONFIG_SECTION_PREFIX):
            continue
        value = field.get('value', '')
        if value:
            sections[label][field['label']] = value

    # Build a HostConfig per section
    hosts = []
    for section_label, ssh_fields in sections.items():
        aliases = _parse_aliases(ssh_fields.get('aliases', ''))
        if not aliases:
            continue

        extra = {k: v for k, v in ssh_fields.items() if k not in _KNOWN_FIELDS}

        hosts.append(HostConfig(
            aliases=aliases,
            hostname=ssh_fields.get('hostname') or None,
            port=ssh_fields.get('port') or None,
            user=ssh_fields.get('user') or None,
            public_key=public_key,
            fingerprint=fingerprint,
            extra_directives=extra,
            section_label=section_label,
            password=ssh_fields.get('password') or None,
        ))

    return hosts


def _parse_aliases(raw: str) -> list[str]:
    """Parse comma-separated aliases with brace expansion.

    Splits on commas that are not inside braces, then expands each part.
    """
    aliases = []
    seen: set[str] = set()
    for part in _split_outside_braces(raw):
        part = part.strip()
        if part:
            for alias in expand_braces(part):
                if alias not in seen:
                    seen.add(alias)
                    aliases.append(alias)
    return aliases


def _split_outside_braces(text: str) -> list[str]:
    """Split on commas that are not inside curly braces."""
    parts = []
    current: list[str] = []
    depth = 0
    for char in text:
        if char == '{':
            depth += 1
            current.append(char)
        elif char == '}':
            depth = max(0, depth - 1)
            current.append(char)
        elif char == ',' and depth == 0:
            parts.append(''.join(current))
            current = []
        else:
            current.append(char)
    parts.append(''.join(current))
    return parts
