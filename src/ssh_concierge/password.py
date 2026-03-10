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


_TTY_PASSTHROUGH = """\
        *)
            printf '[unrecognized prompt] %s' "$1" >/dev/tty
            IFS= read -r reply </dev/tty
            printf '%s\\n' "$reply"
            ;;"""


def _build_askpass_script(
    password_patterns: tuple[str, ...] = ('*assword*',),
    otp_patterns: tuple[str, ...] = (),
) -> str:
    """Generate an askpass shell script with configurable prompt matching.

    Per-host overrides (env vars) are checked first, then global patterns
    baked into the script, then a catch-all tty passthrough.
    """
    lines = ['#!/bin/sh']

    # Per-host password prompt override (env var, checked first)
    lines.append('# Per-host overrides (env vars, checked first)')
    lines.append('if [ -n "$__SSH_CONCIERGE_PW_PROMPT" ]; then')
    lines.append('    case "$1" in')
    lines.append('        $__SSH_CONCIERGE_PW_PROMPT)')
    lines.append("            printf '%s\\n' \"$__SSH_CONCIERGE_PW\"")
    lines.append('            exit 0')
    lines.append('            ;;')
    lines.append('    esac')
    lines.append('fi')

    # Per-host OTP prompt override (env var)
    lines.append('if [ -n "$__SSH_CONCIERGE_OTP_PROMPT" ]; then')
    lines.append('    case "$1" in')
    lines.append('        $__SSH_CONCIERGE_OTP_PROMPT)')
    lines.append('            if [ -n "$__SSH_CONCIERGE_OTP" ]; then')
    lines.append("                printf '%s\\n' \"$__SSH_CONCIERGE_OTP\"")
    lines.append('            else')
    lines.append("                printf '%s' \"$1\" >/dev/tty")
    lines.append('                IFS= read -r reply </dev/tty')
    lines.append("                printf '%s\\n' \"$reply\"")
    lines.append('            fi')
    lines.append('            exit 0')
    lines.append('            ;;')
    lines.append('    esac')
    lines.append('fi')

    # Global patterns baked in from config
    lines.append('# Global defaults (from config.toml, baked in)')
    lines.append('case "$1" in')

    # Password patterns
    if password_patterns:
        pattern = '|'.join(password_patterns)
        lines.append(f'    {pattern})')
        lines.append("        printf '%s\\n' \"$__SSH_CONCIERGE_PW\"")
        lines.append('        ;;')

    # OTP patterns
    if otp_patterns:
        pattern = '|'.join(otp_patterns)
        lines.append(f'    {pattern})')
        lines.append('        if [ -n "$__SSH_CONCIERGE_OTP" ]; then')
        lines.append("            printf '%s\\n' \"$__SSH_CONCIERGE_OTP\"")
        lines.append('        else')
        lines.append("            printf '%s' \"$1\" >/dev/tty")
        lines.append('            IFS= read -r reply </dev/tty')
        lines.append("            printf '%s\\n' \"$reply\"")
        lines.append('        fi')
        lines.append('        ;;')

    # Catch-all: tty passthrough
    lines.append(_TTY_PASSTHROUGH)
    lines.append('esac')
    lines.append('')

    return '\n'.join(lines)


def create_askpass(
    password: str,
    *,
    askpass_dir: Path | None = None,
    password_patterns: tuple[str, ...] = ('*assword*',),
    otp_patterns: tuple[str, ...] = (),
    pw_prompt: str | None = None,
    otp_prompt: str | None = None,
    otp: str | None = None,
) -> dict[str, str]:
    """Create an SSH_ASKPASS script that outputs a password from the environment.

    The script is generated from the given prompt patterns — password prompts
    get the injected value, OTP prompts fall through to tty (or use
    ``__SSH_CONCIERGE_OTP`` if set), everything else passes through.

    Returns a dict of environment variables to merge into the exec env:
      - SSH_ASKPASS: path to the script
      - SSH_ASKPASS_REQUIRE: 'force' (bypass TTY check)
      - __SSH_CONCIERGE_PW: the password value
      - __SSH_CONCIERGE_PW_PROMPT: per-host password prompt override (if set)
      - __SSH_CONCIERGE_OTP_PROMPT: per-host OTP prompt override (if set)
    """
    if askpass_dir is None:
        xdg = os.environ.get('XDG_RUNTIME_DIR')
        askpass_dir = Path(xdg) / 'ssh-concierge' if xdg else Path(tempfile.gettempdir())
    askpass_dir.mkdir(parents=True, exist_ok=True)
    script_path = askpass_dir / 'askpass'

    script_content = _build_askpass_script(password_patterns, otp_patterns)

    # Only write when missing or contents differ.
    needs_write = True
    if script_path.exists():
        try:
            needs_write = script_path.read_text() != script_content
        except OSError:
            pass

    if needs_write:
        script_path.write_text(script_content)
        script_path.chmod(stat.S_IRWXU)  # 0700

    env = {
        'SSH_ASKPASS': str(script_path),
        'SSH_ASKPASS_REQUIRE': 'force',
        '__SSH_CONCIERGE_PW': password,
    }
    if pw_prompt:
        env['__SSH_CONCIERGE_PW_PROMPT'] = pw_prompt
    if otp_prompt:
        env['__SSH_CONCIERGE_OTP_PROMPT'] = otp_prompt
    if otp:
        env['__SSH_CONCIERGE_OTP'] = otp

    return env
