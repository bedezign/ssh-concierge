"""Password resolution and SSH_ASKPASS utilities."""

from __future__ import annotations

import logging
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ssh_concierge.field import resolve_chain
from ssh_concierge.opref import OP_PREFIX, OpRef

if TYPE_CHECKING:
    from ssh_concierge.onepassword import OnePassword

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ItemMeta:
    """Minimal 1Password item metadata needed for op:// reference expansion."""

    vault_id: str
    item_id: str
    vault_name: str = ''
    item_title: str = ''

    @property
    def display_name(self) -> str:
        """Human-readable identifier for error messages."""
        if self.vault_name and self.item_title:
            return f'{self.vault_name}/{self.item_title}'
        return self.item_id or 'unknown'


def normalize_reference(raw: str, item_meta: ItemMeta, section_label: str) -> str:
    """Normalize a raw field value into a full op:// reference.

    - op://./field → op://{vault}/{item}/field
    - op://Vault/Item/field → unchanged
    - op://Vault/Item → append /password (incomplete reference)
    - literal → op://{vault}/{item}/{section}/password  (points back to the field)
    """
    if not raw.startswith(OP_PREFIX) and '://' not in raw:
        # Literal password — construct reference pointing back to the 1Password field
        return f'{OP_PREFIX}{item_meta.vault_id}/{item_meta.item_id}/{section_label}/password'

    return OpRef.parse(raw).normalized(item_meta.vault_id, item_meta.item_id).for_op()


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

    if OpRef.parse(raw_password).is_self_ref and item_meta is None:
        logger.warning(
            'Cannot resolve %s without item metadata — falling back to interactive',
            raw_password,
        )
        return None

    vault_id = item_meta.vault_id if item_meta else None
    item_id = item_meta.item_id if item_meta else None
    return resolve_chain(raw_password, op, vault_id, item_id)


def create_askpass(password: str, *, askpass_dir: Path | None = None) -> dict[str, str]:
    """Create a self-deleting SSH_ASKPASS script.

    Returns a dict of environment variables to merge into the exec env:
      - SSH_ASKPASS: path to the script
      - SSH_ASKPASS_REQUIRE: 'force' (bypass TTY check)

    The script deletes itself after outputting the password, so no cleanup
    is needed by the caller.  Uses askpass_dir if provided, otherwise
    falls back to XDG_RUNTIME_DIR (avoiding /tmp which may be noexec).
    """
    if askpass_dir is None:
        xdg = os.environ.get('XDG_RUNTIME_DIR')
        askpass_dir = Path(xdg) / 'ssh-concierge' if xdg else Path(tempfile.gettempdir())
    askpass_dir.mkdir(parents=True, exist_ok=True)
    fd, script_path = tempfile.mkstemp(prefix='askpass-', dir=askpass_dir)
    # Write the askpass script using a heredoc to avoid shell escaping issues.
    # Delayed self-deletion: SSH may call askpass multiple times (host key
    # verification, then password), so we can't delete on first invocation.
    # A background sleep+rm ensures cleanup after SSH has finished prompting.
    os.write(fd, (
        "#!/bin/sh\n"
        "cat <<'__SSH_CONCIERGE_PW__'\n"
        f"{password}\n"
        "__SSH_CONCIERGE_PW__\n"
        '(sleep 5 && rm -f "$0") >/dev/null 2>&1 &\n'
    ).encode())
    os.close(fd)
    os.chmod(script_path, stat.S_IRWXU)  # 0700

    return {
        'SSH_ASKPASS': script_path,
        'SSH_ASKPASS_REQUIRE': 'force',
    }
