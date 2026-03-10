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


_ASKPASS_SCRIPT = """\
#!/bin/sh
# SSH calls askpass for ALL prompts when SSH_ASKPASS_REQUIRE=force.
# Password prompts get the injected value; everything else (host key
# verification, passphrase) is passed through to the user's terminal.
case "$1" in
    *assword*) printf '%s\\n' "$__SSH_CONCIERGE_PW" ;;
    *)
        printf '%s' "$1" >/dev/tty
        IFS= read -r reply </dev/tty
        printf '%s\\n' "$reply"
        ;;
esac
"""


def create_askpass(password: str, *, askpass_dir: Path | None = None) -> dict[str, str]:
    """Create an SSH_ASKPASS script that outputs a password from the environment.

    The script is generic — it reads ``__SSH_CONCIERGE_PW`` from the process
    environment, so the password never touches disk.  The script is written
    once and reused across connections.

    Returns a dict of environment variables to merge into the exec env:
      - SSH_ASKPASS: path to the script
      - SSH_ASKPASS_REQUIRE: 'force' (bypass TTY check)
      - __SSH_CONCIERGE_PW: the password value
    """
    if askpass_dir is None:
        xdg = os.environ.get('XDG_RUNTIME_DIR')
        askpass_dir = Path(xdg) / 'ssh-concierge' if xdg else Path(tempfile.gettempdir())
    askpass_dir.mkdir(parents=True, exist_ok=True)
    script_path = askpass_dir / 'askpass'

    # Only write when missing or contents differ.
    needs_write = True
    if script_path.exists():
        try:
            needs_write = script_path.read_text() != _ASKPASS_SCRIPT
        except OSError:
            pass

    if needs_write:
        script_path.write_text(_ASKPASS_SCRIPT)
        script_path.chmod(stat.S_IRWXU)  # 0700

    return {
        'SSH_ASKPASS': str(script_path),
        'SSH_ASKPASS_REQUIRE': 'force',
        '__SSH_CONCIERGE_PW': password,
    }
