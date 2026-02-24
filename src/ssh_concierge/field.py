"""Field value model — classification, sensitivity, resolution, caching."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ssh_concierge.onepassword import OnePassword

logger = logging.getLogger(__name__)

OP_REF_PREFIX = 'op://'
OPS_REF_PREFIX = 'ops://'
SELF_PREFIX = './'
CHAIN_SEPARATOR = '||'

SENSITIVE_FIELD_NAMES = frozenset({'password', 'passwd', 'pass', 'secret', 'token'})


def _is_reference(value: str) -> bool:
    """Check if a value segment is a reference (contains ://)."""
    return '://' in value


def _has_template(value: str) -> bool:
    """Check if a value contains {{...}} template syntax."""
    return '{{' in value and '}}' in value


def classify_type(raw: str) -> str:
    """Classify a raw field value as 'reference', 'template', or 'literal'."""
    if _is_reference(raw):
        return 'reference'
    if _has_template(raw):
        return 'template'
    return 'literal'


def is_sensitive(raw: str, field_name: str) -> bool:
    """Determine if a field is sensitive.

    Sensitive if:
    - Any segment in a || chain uses ops:// prefix
    - The field name contains a known sensitive name (e.g. sudo_password, api_token)
    """
    name = field_name.lower()
    return any(s in name for s in SENSITIVE_FIELD_NAMES) or OPS_REF_PREFIX in raw


def normalize_segment(segment: str) -> str:
    """Normalize a single reference segment: ops:// → op://, expand op://. shorthand.

    Self-references (op://./...) require item_meta for full expansion — that
    happens at resolution time. This only handles ops:// → op:// normalization.
    """
    return segment.replace(OPS_REF_PREFIX, OP_REF_PREFIX, 1) if segment.startswith(OPS_REF_PREFIX) else segment


def expand_self_ref(reference: str, vault_id: str, item_id: str) -> str:
    """Expand op://./field → op://{vault_id}/{item_id}/field."""
    self_prefix = f'{OP_REF_PREFIX}{SELF_PREFIX}'
    if reference.startswith(self_prefix):
        suffix = reference[len(self_prefix):]
        return f'{OP_REF_PREFIX}{vault_id}/{item_id}/{suffix}'
    return reference


def normalize_incomplete_ref(reference: str) -> str:
    """Append /password to incomplete op:// references.

    op://Vault/Item (1 slash after op://) → op://Vault/Item/password
    op://Vault/Item/field (2+ slashes) → unchanged
    """
    if not reference.startswith(OP_REF_PREFIX):
        return reference
    path = reference[len(OP_REF_PREFIX):]
    if path.count('/') < 2:
        return f'{reference}/password'
    return reference


def normalize_original(raw: str, vault_id: str, item_id: str) -> str:
    """Normalize self-refs and ops:// in a raw value for storage.

    Expands op://./field → op://vault_id/item_id/field in each segment
    of a || chain so the wrapper can resolve without item metadata.
    Also normalizes incomplete references (appends /password).
    Preserves ops:// prefix (sensitivity marker) — only expands the path.
    """
    segments = raw.split(CHAIN_SEPARATOR)
    normalized = []
    for segment in segments:
        stripped = segment.strip()
        if not stripped or not _is_reference(stripped):
            normalized.append(segment)
            continue

        # Handle ops:// self-refs: ops://./field → ops://vault/item/field
        ops_self = f'{OPS_REF_PREFIX}{SELF_PREFIX}'
        if stripped.startswith(ops_self):
            suffix = stripped[len(ops_self):]
            normalized.append(f'{OPS_REF_PREFIX}{vault_id}/{item_id}/{suffix}')
            continue

        # Handle op:// self-refs
        ref = expand_self_ref(stripped, vault_id, item_id)
        # Normalize incomplete refs
        ref = normalize_incomplete_ref(ref)
        normalized.append(ref)

    return CHAIN_SEPARATOR.join(normalized)


def resolve_chain(
    raw: str,
    op: OnePassword,
    vault_id: str | None = None,
    item_id: str | None = None,
) -> str | None:
    """Resolve a || fallback chain.

    Split on '||', try each segment left-to-right:
    - Segment contains '://' → normalize ops://→op://, expand self-refs, resolve
    - Otherwise → literal (use as-is if non-empty)

    Uses op.read() for reference resolution (cache-aware).
    Returns first non-empty result, or None if all fail.
    """
    segments = raw.split(CHAIN_SEPARATOR)

    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue

        if _is_reference(segment):
            # Normalize ops:// → op://
            ref = normalize_segment(segment)
            # Expand self-references
            if vault_id and item_id:
                ref = expand_self_ref(ref, vault_id, item_id)
            # Normalize incomplete references
            ref = normalize_incomplete_ref(ref)
            result = op.read(ref)
            if result:
                return result
        else:
            # Literal fallback
            return segment

    return None


@dataclass(frozen=True)
class FieldValue:
    """Represents a field value with classification, sensitivity, and resolution state."""

    original: str
    resolved: str | None
    sensitive: bool
    field_type: str  # 'literal', 'reference', 'template'

    @property
    def raw(self) -> str:
        """Raw original value (for expand.py regex/template operations)."""
        return self.original

    @classmethod
    def from_raw(cls, raw: str, field_name: str) -> FieldValue:
        """Create a FieldValue from a raw 1Password field value."""
        return cls(
            original=raw,
            resolved=None,
            field_type=classify_type(raw),
            sensitive=is_sensitive(raw, field_name),
        )

    def with_resolved(self, resolved: str | None) -> FieldValue:
        """Return a new FieldValue with the resolved value set."""
        return FieldValue(
            original=self.original,
            resolved=resolved,
            sensitive=self.sensitive,
            field_type=self.field_type,
        )

    def for_config(self) -> str | None:
        """Value for SSH config output. None if sensitive (excluded)."""
        if self.sensitive:
            return None
        return self.resolved

    def needs_resolution(self, cached: FieldValue | None) -> bool:
        """Check if this field needs resolution (original changed or no cache)."""
        return cached is None or self.original != cached.original

    def resolve(
        self,
        op: OnePassword,
        vault_id: str | None = None,
        item_id: str | None = None,
    ) -> FieldValue:
        """Resolve references and return a new FieldValue with the result.

        Sensitive fields are NOT resolved here (they stay resolved=None).
        Literals and templates use their original value as resolved.
        References are resolved via resolve_chain().

        Uses op.read() for reference resolution (cache-aware).
        """
        if self.sensitive:
            return self

        # Literals and templates both resolve to their original value.
        # (Templates are substituted later during per-alias expansion.)
        if self.field_type in ('literal', 'template'):
            return self.with_resolved(self.original)

        # Reference type — resolve the || chain
        result = resolve_chain(self.original, op, vault_id, item_id)
        return self.with_resolved(result)

    def to_hostdata(self) -> dict:
        """Serialize for the host data cache."""
        return {
            'original': self.original,
            'resolved': self.resolved,
            'sensitive': self.sensitive,
        }

    @classmethod
    def from_hostdata(cls, data: dict, field_name: str) -> FieldValue:
        """Restore from host data cache."""
        original = data['original']
        return cls(
            original=original,
            resolved=data.get('resolved'),
            sensitive=data.get('sensitive', is_sensitive(original, field_name)),
            field_type=classify_type(original),
        )
