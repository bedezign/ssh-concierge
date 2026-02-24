"""Shared test fixtures and helpers."""

from __future__ import annotations

from ssh_concierge.field import FieldValue


def fv(raw: str, name: str = '', resolved: str | None = None) -> FieldValue:
    """Shorthand for creating FieldValue in tests.

    For non-sensitive literals, auto-resolves to the raw value unless
    an explicit resolved value is given.
    """
    f = FieldValue.from_raw(raw, name)
    if resolved is not None:
        return f.with_resolved(resolved)
    # Auto-resolve non-sensitive literals (common in tests)
    if f.field_type == 'literal' and not f.sensitive:
        return f.with_resolved(raw)
    return f
