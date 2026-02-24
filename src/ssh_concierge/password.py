"""Password resolution and SSH_ASKPASS utilities."""

from __future__ import annotations

import logging
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from ssh_concierge.field import (
    OP_REF_PREFIX,
    expand_self_ref,
    normalize_incomplete_ref,
    resolve_chain,
)

if TYPE_CHECKING:
    from ssh_concierge.onepassword import OnePassword

logger = logging.getLogger(__name__)

OP_SELF_PREFIX = f'{OP_REF_PREFIX}./'


@dataclass(frozen=True)
class ItemMeta:
    """Minimal 1Password item metadata needed for op:// reference expansion."""

    vault_id: str
    item_id: str


def normalize_reference(raw: str, item_meta: ItemMeta, section_label: str) -> str:
    """Normalize a raw field value into a full op:// reference.

    - op://./field → op://{vault}/{item}/field
    - op://Vault/Item/field → unchanged
    - op://Vault/Item → append /password (incomplete reference)
    - literal → op://{vault}/{item}/{section}/password  (points back to the field)
    """
    if raw.startswith(OP_SELF_PREFIX):
        return expand_self_ref(raw, item_meta.vault_id, item_meta.item_id)

    if raw.startswith(OP_REF_PREFIX):
        return normalize_incomplete_ref(raw)

    # Literal password — construct reference pointing back to the 1Password field
    return f'{OP_REF_PREFIX}{item_meta.vault_id}/{item_meta.item_id}/{section_label}/password'


# Keep backward compat alias
build_op_reference = normalize_reference


def resolve_password(
    raw_password: str | None,
    op: OnePassword,
    item_meta: ItemMeta | None = None,
) -> str | None:
    """Resolve a password value from a raw field string.

    Supports:
      - None / empty → None
      - Literal value (no op:// or other :// prefix) → returned as-is
      - op://./field → expanded to full op:// ref, then read
      - op://Vault/Item/field → read directly via `op read`
      - || fallback chains

    Returns None on resolution failure (caller falls back to interactive).
    """
    if not raw_password:
        return None

    if '://' not in raw_password:
        return raw_password

    if raw_password.startswith(OP_SELF_PREFIX) and item_meta is None:
        logger.warning(
            'Cannot resolve %s without item metadata — falling back to interactive',
            raw_password,
        )
        return None

    vault_id = item_meta.vault_id if item_meta else None
    item_id = item_meta.item_id if item_meta else None
    return resolve_chain(raw_password, op, vault_id, item_id)


@contextmanager
def askpass_env(password: str) -> Iterator[dict[str, str]]:
    """Context manager that creates a temporary SSH_ASKPASS script.

    Yields a dict of environment variables to merge into subprocess env:
      - SSH_ASKPASS: path to the temp script
      - SSH_ASKPASS_REQUIRE: 'force' (bypass TTY check)

    The script is cleaned up on exit.
    """
    fd, script_path = tempfile.mkstemp(prefix='ssh-concierge-askpass-')
    try:
        # Write the askpass script — just echoes the password
        os.write(fd, f'#!/bin/sh\necho "{_shell_escape(password)}"\n'.encode())
        os.close(fd)
        os.chmod(script_path, stat.S_IRWXU)  # 0700

        yield {
            'SSH_ASKPASS': script_path,
            'SSH_ASKPASS_REQUIRE': 'force',
        }
    finally:
        try:
            Path(script_path).unlink(missing_ok=True)
        except OSError:
            pass


def _shell_escape(value: str) -> str:
    """Escape a value for use inside double quotes in a shell script."""
    return value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
