"""Password resolution and SSH_ASKPASS utilities."""

from __future__ import annotations

import logging
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

OP_REF_PREFIX = 'op://'
OP_SELF_PREFIX = 'op://./'


@dataclass(frozen=True)
class ItemMeta:
    """Minimal 1Password item metadata needed for op:// reference expansion."""

    vault_id: str
    item_id: str


def build_op_reference(raw_password: str, item_meta: ItemMeta, section_label: str) -> str:
    """Convert a raw password value to a full op:// reference.

    - op://./field → op://{vault}/{item}/field
    - op://Vault/Item/field → unchanged
    - op://Vault/Item → append /password (incomplete reference)
    - literal → op://{vault}/{item}/{section}/password  (points back to the field)
    """
    if raw_password.startswith(OP_SELF_PREFIX):
        suffix = raw_password[len(OP_SELF_PREFIX):]
        return f'op://{item_meta.vault_id}/{item_meta.item_id}/{suffix}'

    if raw_password.startswith(OP_REF_PREFIX):
        # op://vault/item has 1 slash after op://, op://vault/item/field has 2+
        path = raw_password[len(OP_REF_PREFIX):]
        if path.count('/') < 2:
            return f'{raw_password}/password'
        return raw_password

    # Literal password — construct reference pointing back to the 1Password field
    return f'op://{item_meta.vault_id}/{item_meta.item_id}/{section_label}/password'


def resolve_password(
    raw_password: str | None,
    item_meta: ItemMeta | None = None,
) -> str | None:
    """Resolve a password value from a raw field string.

    Supports:
      - None / empty → None
      - Literal value (no op:// prefix) → returned as-is
      - op://./field or op://./Section/field → expanded to full op:// ref, then read
      - op://Vault/Item/field → read directly via `op read`

    Returns None on resolution failure (caller falls back to interactive).
    """
    if not raw_password:
        return None

    if not raw_password.startswith(OP_REF_PREFIX):
        return raw_password

    # Expand op://. shorthand
    reference = raw_password
    if reference.startswith(OP_SELF_PREFIX):
        if item_meta is None:
            logger.warning(
                'Cannot resolve %s without item metadata — falling back to interactive',
                reference,
            )
            return None
        suffix = reference[len(OP_SELF_PREFIX):]
        reference = f'op://{item_meta.vault_id}/{item_meta.item_id}/{suffix}'

    # Call op read
    from ssh_concierge.onepassword import OpError, _run_op

    try:
        return _run_op(['read', reference]).strip()
    except OpError as exc:
        logger.warning('Failed to resolve password reference %s: %s', raw_password, exc)
        return None


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
