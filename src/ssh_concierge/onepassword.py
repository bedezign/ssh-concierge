"""1Password op CLI wrapper for SSH config items."""

from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict
from typing import Any

from ssh_concierge.expand import expand_braces
from ssh_concierge.models import HostConfig

# Fields from the "SSH Config" section that map to HostConfig attributes directly
_KNOWN_FIELDS = {'aliases', 'alias', 'hostname', 'host', 'port', 'user', 'username', 'password', 'clipboard', 'key'}

# Valid SSH client config keywords (from man ssh_config, OpenSSH 8.x-9.x).
# Maps lowercase → canonical casing. User input is normalized to the canonical form.
# Excludes keywords we generate ourselves: Host, Match, Include, HostName, Port,
# User, IdentityFile, IdentitiesOnly.
_VALID_SSH_DIRECTIVES: dict[str, str] = {k.lower(): k for k in (
    'AddKeysToAgent',
    'AddressFamily',
    'BatchMode',
    'BindAddress',
    'BindInterface',
    'CanonicalDomains',
    'CanonicalizeFallbackLocal',
    'CanonicalizeHostname',
    'CanonicalizeMaxDots',
    'CanonicalizePermittedCNAMEs',
    'CASignatureAlgorithms',
    'CertificateFile',
    'ChannelTimeout',
    'CheckHostIP',
    'Ciphers',
    'ClearAllForwardings',
    'Compression',
    'ConnectionAttempts',
    'ConnectTimeout',
    'ControlMaster',
    'ControlPath',
    'ControlPersist',
    'DynamicForward',
    'EnableEscapeCommandline',
    'EnableSSHKeysign',
    'EscapeChar',
    'ExitOnForwardFailure',
    'FingerprintHash',
    'ForkAfterAuthentication',
    'ForwardAgent',
    'ForwardX11',
    'ForwardX11Timeout',
    'ForwardX11Trusted',
    'GatewayPorts',
    'GlobalKnownHostsFile',
    'GSSAPIAuthentication',
    'GSSAPIDelegateCredentials',
    'GSSAPIKeyExchange',
    'GSSAPIRenewalForcesRekey',
    'GSSAPIServerIdentity',
    'GSSAPITrustDns',
    'HashKnownHosts',
    'HostbasedAcceptedAlgorithms',
    'HostbasedAuthentication',
    'HostKeyAlgorithms',
    'HostKeyAlias',
    'IdentityAgent',
    'IgnoreUnknown',
    'IPQoS',
    'KbdInteractiveAuthentication',
    'KbdInteractiveDevices',
    'KexAlgorithms',
    'KnownHostsCommand',
    'LocalCommand',
    'LocalForward',
    'LogLevel',
    'LogVerbose',
    'MACs',
    'NoHostAuthenticationForLocalhost',
    'NumberOfPasswordPrompts',
    'ObfuscateKeystrokes',
    'PasswordAuthentication',
    'PermitLocalCommand',
    'PermitRemoteOpen',
    'PKCS11Provider',
    'PreferredAuthentications',
    'ProxyCommand',
    'ProxyJump',
    'ProxyUseFdpass',
    'PubkeyAcceptedAlgorithms',
    'PubkeyAuthentication',
    'RekeyLimit',
    'RemoteCommand',
    'RemoteForward',
    'RequestTTY',
    'RequiredRSASize',
    'RevokedHostKeys',
    'SecurityKeyProvider',
    'SendEnv',
    'ServerAliveCountMax',
    'ServerAliveInterval',
    'SessionType',
    'SetEnv',
    'StreamLocalBindMask',
    'StreamLocalBindUnlink',
    'StrictHostKeyChecking',
    'SyslogFacility',
    'TCPKeepAlive',
    'Tunnel',
    'TunnelDevice',
    'UpdateHostKeys',
    'UseKeychain',
    'UserKnownHostsFile',
    'VerifyHostKeyDNS',
    'VisualHostKey',
    'XAuthLocation',
)}

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

    # Group fields by section (only SSH Config* sections).
    # Each section maps lowercase field name → (original_label, value)
    # so known-field lookups are case-insensitive while extra directives
    # preserve the user's original casing.
    sections: dict[str, dict[str, tuple[str, str]]] = defaultdict(dict)
    for field in fields:
        section = field.get('section')
        if not section:
            continue
        label = section.get('label', '')
        if not label.startswith(SSH_CONFIG_SECTION_PREFIX):
            continue
        value = field.get('value', '')
        if value:
            original_label = field['label']
            sections[label][original_label.lower()] = (original_label, value)

    # Build a HostConfig per section
    hosts = []
    for section_label, ssh_fields in sections.items():
        aliases_val = (
            ssh_fields.get('aliases', (None, ''))[1]
            or ssh_fields.get('alias', (None, ''))[1]
        )
        aliases = _parse_aliases(aliases_val)
        if not aliases:
            continue

        extra_raw = {k: v for k, (_orig, v) in ssh_fields.items() if k not in _KNOWN_FIELDS}

        invalid = [k for k in extra_raw if k not in _VALID_SSH_DIRECTIVES]
        if invalid:
            title = item.get('title', item.get('id', '?'))
            for key in invalid:
                orig = ssh_fields[key][0]
                print(
                    f'ssh-concierge: skipping "{title}" [{section_label}]: '
                    f'unknown SSH directive "{orig}"',
                    file=sys.stderr,
                )
            continue

        # Normalize to canonical SSH config casing
        extra = {_VALID_SSH_DIRECTIVES[k]: v for k, v in extra_raw.items()}

        def _val(key: str) -> str | None:
            entry = ssh_fields.get(key)
            return entry[1] if entry else None

        hosts.append(HostConfig(
            aliases=aliases,
            hostname=_val('hostname') or _val('host'),
            port=_val('port'),
            user=_val('user') or _val('username'),
            public_key=public_key,
            fingerprint=fingerprint,
            extra_directives=extra,
            section_label=section_label,
            password=_val('password'),
            clipboard=_val('clipboard'),
            key_ref=_val('key'),
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
