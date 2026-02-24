"""Expansion utilities: brace expansion for aliases, regex/template substitution for directives."""

from __future__ import annotations

import re

from ssh_concierge.models import HostConfig

_BRACE_RE = re.compile(r'^(.*?)\{([^}]+)\}(.*)$')
_ALIAS_PLACEHOLDER = '{{alias}}'


def expand_braces(pattern: str) -> list[str]:
    """Expand a single brace expression in a string.

    Supports:
      - Comma lists: host{1,2,3} → host1, host2, host3
      - Ranges: worker{1..8} → worker1, ..., worker8
    """
    match = _BRACE_RE.match(pattern)
    if not match:
        return [pattern]

    prefix, expr, suffix = match.groups()

    # Range: {1..8}
    range_match = re.match(r'^(\d+)\.\.(\d+)$', expr)
    if range_match:
        start, end = int(range_match.group(1)), int(range_match.group(2))
        return [f'{prefix}{i}{suffix}' for i in range(start, end + 1)]

    # Comma list: {a,b,c}
    if ',' in expr:
        parts = [p.strip() for p in expr.split(',')]
        return [f'{prefix}{p}{suffix}' for p in parts]

    # No valid expansion syntax
    return [pattern]


def _is_regex(value: str | None) -> bool:
    """Check if a value is a sed-style regex substitution."""
    return bool(value and value.startswith('s/') and value.count('/') >= 3)


def _has_alias(value: str | None) -> bool:
    """Check if a value contains the {{alias}} placeholder."""
    return bool(value and _ALIAS_PLACEHOLDER in value)


def _needs_per_alias_expansion(host: HostConfig) -> bool:
    """Check if any field needs per-alias expansion (regex or {{alias}} template)."""
    for value in _iter_field_values(host):
        if _is_regex(value) or _has_alias(value):
            return True
    return False


def _iter_field_values(host: HostConfig):
    """Yield all expandable field values from a HostConfig."""
    yield host.hostname
    yield host.user
    yield from host.extra_directives.values()


def _resolve(value: str | None, alias: str) -> str | None:
    """Resolve a field value for a given alias.

    Supports:
      - s/pattern/replacement/ — regex substitution
      - {{alias}} — simple placeholder interpolation
      - anything else — returned as-is
    """
    if value is None:
        return None
    if _is_regex(value):
        parts = value.split('/')
        return re.sub(parts[1], parts[2], alias)
    if _has_alias(value):
        return value.replace(_ALIAS_PLACEHOLDER, alias)
    return value


def expand_host_config(host: HostConfig) -> list[HostConfig]:
    """Expand a HostConfig into individual HostConfigs per alias.

    Triggered when any field uses regex (s/.../.../} or {{alias}} placeholder.
    Each alias gets its own HostConfig with resolved values.

    Fields without regex or {{alias}} are passed through unchanged.
    """
    if not _needs_per_alias_expansion(host):
        return [host]

    result = []
    for alias in host.aliases:
        result.append(HostConfig(
            aliases=[alias],
            hostname=_resolve(host.hostname, alias),
            port=host.port,
            user=_resolve(host.user, alias),
            public_key=host.public_key,
            fingerprint=host.fingerprint,
            extra_directives={
                k: _resolve(v, alias) or v
                for k, v in host.extra_directives.items()
            },
            section_label=host.section_label,
            password=host.password,
            clipboard=host.clipboard,
            key_ref=host.key_ref,
        ))

    return result
