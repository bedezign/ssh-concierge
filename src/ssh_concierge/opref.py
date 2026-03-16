"""1Password op:// URI parser with support for quoted and URL-encoded item names.

Reference format:
  Field refs (3 segments):  op://Vault/Item/field, op://./Item/field, op://././field
  Item refs (2 segments):   op://Vault/Item, op://./Item
  Sensitive:                ops://... (same as op:// but marks field as sensitive)

The '.' marker means "current" at any position:
  - Vault position: current vault (same-vault ref)
  - Item position: current item (only valid when vault is also '.')
"""

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
        - op://Vault/Item/field          (fully explicit field ref)
        - op://./Item/field              (same-vault cross-item field ref)
        - op://././field                 (self-ref field ref)
        - op://Vault/Item                (item-level ref, e.g. key refs)
        - op://./Item                    (same-vault item ref)
        - op://Vault/"Item / Slash"/f    (quoted item names)
        - op://Vault/Item %2F Name/f    (URL-encoded)
        - ops://...                      (sensitive marker)

        Rejected:
        - op://Vault/./field  (. in item requires . in vault)
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

        if len(parts) < 2 or not parts[1]:
            raise ValueError(f'Invalid reference (need vault/item): {uri}')

        vault = parts[0]
        item = parts[1]
        field_path = '/'.join(parts[2:]) if len(parts) > 2 and parts[2] else None

        # Validate: . in item position requires . in vault position
        if item == SELF_MARKER and vault != SELF_MARKER:
            raise ValueError(
                f'Invalid reference: "." in item position requires "." in vault '
                f'position (use op://././field for self-refs): {uri}'
            )

        return cls(vault=vault, item=item, field_path=field_path, sensitive=sensitive)

    @property
    def is_self_ref(self) -> bool:
        """Whether this is a self-reference (op://././...)."""
        return self.vault == SELF_MARKER and self.item == SELF_MARKER

    @property
    def is_same_vault(self) -> bool:
        """Whether this references the current vault (op://./...)."""
        return self.vault == SELF_MARKER

    @property
    def is_complete(self) -> bool:
        """Whether this reference includes a field path (not just vault/item)."""
        return self.field_path is not None

    def with_field(self, field_path: str) -> OpRef:
        """Return a new OpRef with the given field path."""
        return OpRef(vault=self.vault, item=self.item, field_path=field_path, sensitive=self.sensitive)

    def expand_dots(self, vault_id: str, item_id: str) -> OpRef:
        """Expand '.' markers to actual vault/item IDs.

        - op://././field → op://vault_id/item_id/field
        - op://./Item/field → op://vault_id/Item/field
        - Non-dot refs → unchanged
        """
        if not self.is_same_vault:
            return self
        new_vault = vault_id
        new_item = item_id if self.item == SELF_MARKER else self.item
        return OpRef(vault=new_vault, item=new_item, field_path=self.field_path, sensitive=self.sensitive)

    def normalized(self, vault_id: str | None = None, item_id: str | None = None) -> OpRef:
        """Expand dot-refs to full references.

        - op://././field with vault_id/item_id → op://vault_id/item_id/field
        - op://./Item/field with vault_id → op://vault_id/Item/field
        - Already full refs → unchanged
        """
        if self.is_same_vault and vault_id:
            return self.expand_dots(vault_id, item_id or '')
        return self

    def for_op(self) -> str:
        """Emit URI for the op CLI: always op:// prefix, %2F-encoded names."""
        return self._to_uri(OP_PREFIX)

    def for_storage(self) -> str:
        """Emit URI for storage: preserves ops:// sensitivity marker, %2F-encoded."""
        return self._to_uri(OPS_PREFIX if self.sensitive else OP_PREFIX)

    def _to_uri(self, prefix: str) -> str:
        vault = _encode_part(self.vault)
        item = _encode_part(self.item)

        if self.field_path is not None:
            return f'{prefix}{vault}/{item}/{self.field_path}'
        return f'{prefix}{vault}/{item}'
