"""1Password op:// URI parser with support for quoted and URL-encoded item names."""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

OP_PREFIX = 'op://'
OPS_PREFIX = 'ops://'
SELF_MARKER = '.'


def _encode_part(value: str) -> str:
    """Encode slashes in a vault/item name for the op CLI (/ → %2F)."""
    return value.replace('/', '%2F')


def _split_uri_path(path: str) -> list[str]:
    """Split an op:// path into parts, respecting double-quoted segments.

    Handles:
    - Regular: Vault/Item/field → ['Vault', 'Item', 'field']
    - Quoted: Vault/"Item / Name"/field → ['Vault', 'Item / Name', 'field']
    - URL-encoded: Vault/Item %2F Name/field → ['Vault', 'Item / Name', 'field']

    Splitting happens on unquoted, literal '/' characters. After splitting,
    each part is URL-decoded (%2F → /) and surrounding double quotes are stripped.
    """
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False

    for ch in path:
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == '/' and not in_quotes:
            parts.append(urllib.parse.unquote(''.join(current)))
            current = []
        else:
            current.append(ch)

    if current:
        parts.append(urllib.parse.unquote(''.join(current)))

    return parts


@dataclass(frozen=True)
class OpRef:
    """Parsed 1Password op:// reference.

    Provides structured access to vault, item, and field path components,
    with methods to emit the URI in different formats (for CLI, for storage).
    """

    vault: str
    item: str
    field_path: str | None
    sensitive: bool

    @classmethod
    def parse(cls, uri: str) -> OpRef:
        """Parse an op:// URI into components.

        Supports:
        - op://Vault/Item/field
        - op://Vault/"Item With / Slash"/field  (quoted)
        - op://Vault/Item %2F Name/field  (URL-encoded)
        - op://./field  (self-reference)
        - ops://...  (sensitive marker)
        - Vault/Item  (no prefix, for key refs)
        """
        sensitive = uri.startswith(OPS_PREFIX)

        if sensitive:
            path = uri[len(OPS_PREFIX):]
        elif uri.startswith(OP_PREFIX):
            path = uri[len(OP_PREFIX):]
        else:
            path = uri

        parts = _split_uri_path(path)

        if not parts or not parts[0]:
            raise ValueError(f'Invalid reference: {uri}')

        # Self-reference: op://./field or op://./Section/field
        if parts[0] == SELF_MARKER:
            field_path = '/'.join(parts[1:]) if len(parts) > 1 else None
            return cls(vault=SELF_MARKER, item='', field_path=field_path, sensitive=sensitive)

        if len(parts) < 2 or not parts[1]:
            raise ValueError(f'Invalid reference (need vault/item): {uri}')

        vault = parts[0]
        item = parts[1]
        field_path = '/'.join(parts[2:]) if len(parts) > 2 and parts[2] else None

        return cls(vault=vault, item=item, field_path=field_path, sensitive=sensitive)

    @property
    def is_self_ref(self) -> bool:
        """Whether this is a self-reference (op://./...)."""
        return self.vault == SELF_MARKER

    @property
    def is_complete(self) -> bool:
        """Whether this reference includes a field path (not just vault/item)."""
        return self.field_path is not None

    def with_field(self, field_path: str) -> OpRef:
        """Return a new OpRef with the given field path."""
        return OpRef(vault=self.vault, item=self.item, field_path=field_path, sensitive=self.sensitive)

    def expand_self(self, vault_id: str, item_id: str) -> OpRef:
        """Expand a self-reference (op://./...) to a full reference."""
        if not self.is_self_ref:
            return self
        return OpRef(vault=vault_id, item=item_id, field_path=self.field_path, sensitive=self.sensitive)

    def normalized(self, vault_id: str | None = None, item_id: str | None = None, *, default_field: str = 'password') -> OpRef:
        """Expand self-refs and complete incomplete references.

        - op://./field with vault_id/item_id → op://vault_id/item_id/field
        - op://Vault/Item (no field) → op://Vault/Item/{default_field}
        - Already complete non-self refs → unchanged
        """
        ref = self
        if ref.is_self_ref and vault_id and item_id:
            ref = ref.expand_self(vault_id, item_id)
        if not ref.is_complete:
            ref = ref.with_field(default_field)
        return ref

    def for_op(self) -> str:
        """Emit URI for the op CLI: always op:// prefix, %2F-encoded names."""
        return self._to_uri(OP_PREFIX)

    def for_storage(self) -> str:
        """Emit URI for storage: preserves ops:// sensitivity marker, %2F-encoded."""
        return self._to_uri(OPS_PREFIX if self.sensitive else OP_PREFIX)

    def _to_uri(self, prefix: str) -> str:
        if self.is_self_ref:
            base = f'{prefix}{SELF_MARKER}'
            return f'{base}/{self.field_path}' if self.field_path else base

        vault = _encode_part(self.vault)
        item = _encode_part(self.item)

        if self.field_path is not None:
            return f'{prefix}{vault}/{item}/{self.field_path}'
        return f'{prefix}{vault}/{item}'
