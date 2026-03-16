"""Field value model — classification, sensitivity, resolution, caching."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ssh_concierge.opref import OP_PREFIX, OPS_PREFIX, OpRef

if TYPE_CHECKING:
    from ssh_concierge.onepassword import OnePassword

logger = logging.getLogger(__name__)

CHAIN_SEPARATOR = '||'
TEMPLATE_OPEN = '{{'
TEMPLATE_CLOSE = '}}'

SENSITIVE_FIELD_NAMES = frozenset({'password', 'passwd', 'pass', 'secret', 'token', 'otp'})

# Field names whose item-level refs (op://Vault/Item) auto-complete with a field path.
_AUTO_COMPLETE_FIELDS: dict[str, str] = {
    'password': 'password',
}


def _is_reference(value: str) -> bool:
    """Check if a value segment is a reference (contains ://)."""
    return '://' in value


def _has_template(value: str) -> bool:
    """Check if a value contains {{...}} template syntax."""
    return TEMPLATE_OPEN in value and TEMPLATE_CLOSE in value


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
    return any(s in name for s in SENSITIVE_FIELD_NAMES) or OPS_PREFIX in raw


def complete_field_refs(raw: str, field_name: str) -> str:
    """Ensure all reference segments in a raw value have a field path.

    Item-level refs (op://Vault/Item) are valid for ``key`` but not for fields
    resolved via ``op read``.  For known fields (e.g. password) the field path
    is auto-appended; for anything else a ValueError is raised.

    Non-reference segments and complete references are passed through unchanged.
    """
    segments = raw.split(CHAIN_SEPARATOR)
    result: list[str] = []
    for segment in segments:
        stripped = segment.strip()
        if not stripped or not _is_reference(stripped):
            result.append(segment)
            continue

        ref = OpRef.parse(stripped)
        if ref.is_complete:
            result.append(segment)
            continue

        auto_field = _AUTO_COMPLETE_FIELDS.get(field_name)
        if auto_field:
            completed = ref.with_field(auto_field)
            logger.warning(
                'Incomplete reference "%s" in field "%s" — auto-completed to "%s"',
                stripped,
                field_name,
                completed.for_storage(),
            )
            result.append(segment.replace(stripped, completed.for_storage()))
        else:
            raise ValueError(
                f'incomplete reference (missing field path): {stripped}'
            )

    return CHAIN_SEPARATOR.join(result)


def normalize_original(raw: str, vault_id: str, item_id: str) -> str:
    """Normalize dot-refs and ops:// in a raw value for storage.

    Expands op://././field → op://vault_id/item_id/field and
    op://./Item/field → op://vault_id/Item/field in each segment
    of a || chain so the wrapper can resolve without item metadata.
    Preserves ops:// prefix (sensitivity marker) — only expands the path.
    """
    segments = raw.split(CHAIN_SEPARATOR)
    normalized = []
    for segment in segments:
        stripped = segment.strip()
        if not stripped or not _is_reference(stripped):
            normalized.append(segment)
            continue

        normalized.append(OpRef.parse(stripped).normalized(vault_id, item_id).for_storage())

    return CHAIN_SEPARATOR.join(normalized)


def _resolve_ref_segment(segment: str, op: OnePassword, vault_id: str | None, item_id: str | None, *, cache_only: bool) -> str | None:
    """Resolve a single reference segment using OpRef."""
    return op.read(OpRef.parse(segment).normalized(vault_id, item_id).for_op(), cache_only=cache_only)


def resolve_chain(
    raw: str,
    op: OnePassword,
    vault_id: str | None = None,
    item_id: str | None = None,
    *,
    cache_only: bool = False,
) -> str | None:
    """Resolve a || fallback chain.

    Split on '||', try each segment left-to-right:
    - Segment contains '://' → parse as OpRef, normalize, resolve via op.read()
    - Otherwise → literal (use as-is if non-empty)

    Uses op.read() for reference resolution (cache-aware).
    If cache_only=True, only uses cached values (no CLI calls).
    Returns first non-empty result, or None if all fail.
    """
    segments = raw.split(CHAIN_SEPARATOR)

    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue

        if _is_reference(segment):
            result = _resolve_ref_segment(segment, op, vault_id, item_id, cache_only=cache_only)
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
