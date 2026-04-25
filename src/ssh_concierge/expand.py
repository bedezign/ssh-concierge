"""Expansion utilities: regex/template substitution for directives."""

from __future__ import annotations

import re

from op_core import FieldValue, classify_type

from ssh_concierge.models import HostConfig

_ALIAS_PLACEHOLDER = "{{alias}}"


def _needs_per_alias_expansion(host: HostConfig) -> bool:
    """Check if any field needs per-alias expansion (regex or {{alias}} template)."""
    return any(
        (v.startswith("s/") and v.count("/") >= 3) or _ALIAS_PLACEHOLDER in v
        for v in _iter_field_values(host)
    )


def _iter_field_values(host: HostConfig):
    """Yield all expandable raw field values from a HostConfig."""
    if host.hostname:
        yield host.hostname.original
    if host.user:
        yield host.user.original
    for fv in host.extra_directives.values():
        yield fv.original


def _resolve_fv(fv: FieldValue | None, alias: str) -> FieldValue | None:
    """Resolve a FieldValue for a given alias.

    Supports:
      - s/pattern/replacement/ — regex substitution on the original value
      - {{alias}} — simple placeholder interpolation on the original value
      - anything else — returned as-is
    """
    if fv is None:
        return None

    original = fv.original
    if original.startswith("s/") and original.count("/") >= 3:
        parts = original.split("/")
        new_val = re.sub(parts[1], parts[2], alias)
        return FieldValue(
            original=new_val,
            resolved=None,
            sensitive=fv.sensitive,
            field_type="literal",
        )
    if _ALIAS_PLACEHOLDER in original:
        new_val = original.replace(_ALIAS_PLACEHOLDER, alias)
        return FieldValue(
            original=new_val,
            resolved=None,
            sensitive=fv.sensitive,
            field_type=classify_type(new_val),
        )
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
            extra_directives={
                k: _resolve_fv(fv, alias) or fv
                for k, fv in host.extra_directives.items()
            },
            custom_fields=host.custom_fields,
            section_label=host.section_label,
            password=host.password,
            otp=host.otp,
            clipboard=host.clipboard,
            key_ref=host.key_ref,
            host_filter=host.host_filter,
            password_prompt=host.password_prompt,
            otp_prompt=host.otp_prompt,
        )
        for alias in host.aliases
    ]
