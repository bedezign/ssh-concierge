"""Expansion utilities: brace expansion for aliases, regex/template substitution for directives."""

from __future__ import annotations

import re

from ssh_concierge.field import TEMPLATE_CLOSE, TEMPLATE_OPEN, FieldValue, classify_type
from ssh_concierge.models import HostConfig

_BRACE_RE = re.compile(r'^(.*?)\{([^}]+)\}(.*)$')
_ALIAS_PLACEHOLDER = f'{TEMPLATE_OPEN}alias{TEMPLATE_CLOSE}'


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
    return any(_is_regex(v) or _has_alias(v) for v in _iter_field_values(host))


def _iter_field_values(host: HostConfig):
    """Yield all expandable raw field values from a HostConfig."""
    if host.hostname:
        yield host.hostname.raw
    if host.user:
        yield host.user.raw
    for fv in host.extra_directives.values():
        yield fv.raw


def _resolve_fv(fv: FieldValue | None, alias: str) -> FieldValue | None:
    """Resolve a FieldValue for a given alias.

    Supports:
      - s/pattern/replacement/ — regex substitution on the raw value
      - {{alias}} — simple placeholder interpolation on the raw value
      - anything else — returned as-is
    """
    if fv is None:
        return None

    raw = fv.raw
    if _is_regex(raw):
        parts = raw.split('/')
        new_val = re.sub(parts[1], parts[2], alias)
        return FieldValue(original=new_val, resolved=None, sensitive=fv.sensitive, field_type='literal')
    if _has_alias(raw):
        new_val = raw.replace(_ALIAS_PLACEHOLDER, alias)
        return FieldValue(original=new_val, resolved=None, sensitive=fv.sensitive, field_type=classify_type(new_val))
    return fv


def expand_host_config(host: HostConfig) -> list[HostConfig]:
    """Expand a HostConfig into individual HostConfigs per alias.

    Triggered when any field uses regex (s/.../.../} or {{alias}} placeholder.
    Each alias gets its own HostConfig with resolved values.

    Fields without regex or {{alias}} are passed through unchanged.
    """
    if not _needs_per_alias_expansion(host):
        return [host]

    return [
        HostConfig(
            aliases=[alias],
            hostname=_resolve_fv(host.hostname, alias),
            port=host.port,
            user=_resolve_fv(host.user, alias),
            public_key=host.public_key,
            fingerprint=host.fingerprint,
            extra_directives={k: _resolve_fv(fv, alias) or fv for k, fv in host.extra_directives.items()},
            custom_fields=host.custom_fields,
            section_label=host.section_label,
            password=host.password,
            clipboard=host.clipboard,
            key_ref=host.key_ref,
            host_filter=host.host_filter,
        )
        for alias in host.aliases
    ]
