"""SSH/SCP wrapper with transparent password injection and clipboard from 1Password."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from ssh_concierge.argparse_ssh import extract_scp_host, extract_ssh_host
from ssh_concierge.password import askpass_env

logger = logging.getLogger(__name__)


def _default_runtime_dir() -> Path:
    xdg = os.environ.get('XDG_RUNTIME_DIR')
    if xdg:
        return Path(xdg) / 'ssh-concierge'
    return Path('/tmp') / f'ssh-concierge-{os.getuid()}'


def find_real_binary(tool: str) -> str | None:
    """Find the real ssh/scp binary in PATH, skipping the wrapper itself.

    Compares resolved paths to avoid finding ourselves.
    """
    wrapper_path = Path(sys.argv[0]).resolve()

    for entry in os.environ.get('PATH', '').split(os.pathsep):
        candidate = Path(entry) / tool
        if candidate.is_file() and os.access(candidate, os.X_OK):
            if candidate.resolve() != wrapper_path:
                return str(candidate)

    return None


def lookup_hostdata(host: str, hostdata_path: Path) -> dict[str, Any] | None:
    """Look up a host entry in hostdata.json."""
    if not hostdata_path.is_file():
        return None
    try:
        data = json.loads(hostdata_path.read_text())
        return data.get(host)
    except (json.JSONDecodeError, OSError):
        return None


def lookup_reference(host: str, hostdata_path: Path) -> str | None:
    """Look up an op:// password reference for a host.

    Compat wrapper over lookup_hostdata for cmd_debug backward compatibility.
    """
    entry = lookup_hostdata(host, hostdata_path)
    if entry:
        return entry.get('refs', {}).get('password')
    return None


def resolve_via_op_read(reference: str) -> str | None:
    """Resolve an op:// reference to a plaintext value via `op read`."""
    from ssh_concierge.onepassword import OpError, _run_op

    try:
        return _run_op(['read', reference]).strip()
    except OpError as exc:
        print(f'ssh-concierge: op read failed: {exc}', file=sys.stderr)
        return None


def _resolve_refs(refs: dict[str, str]) -> dict[str, str] | None:
    """Resolve all refs, returning resolved dict or None on any op:// failure."""
    resolved: dict[str, str] = {}
    for name, value in refs.items():
        if value.startswith('op://'):
            result = resolve_via_op_read(value)
            if result is None:
                return None
            resolved[name] = result
        else:
            resolved[name] = value
    return resolved


def resolve_clipboard(template: str, resolved: dict[str, str]) -> str:
    """Substitute {field_name} placeholders and process \\n → newlines.

    Unrecognized placeholders are left as-is.
    Both literal \\n (two chars) and real newlines are supported.
    """
    result = template
    for name, value in resolved.items():
        result = result.replace(f'{{{name}}}', value)
    # Replace literal \n (two chars: backslash + n) with real newlines.
    # Real newlines from multi-line 1Password fields are already newlines.
    result = result.replace('\\n', '\n')
    return result


def copy_to_clipboard(value: str) -> bool:
    """Copy value to system clipboard. Returns True on success."""
    wayland = os.environ.get('WAYLAND_DISPLAY')
    if wayland:
        cmd = ['wl-copy']
    elif os.environ.get('DISPLAY'):
        cmd = ['xclip', '-selection', 'clipboard']
    else:
        print('ssh-concierge: no clipboard tool available (no WAYLAND_DISPLAY or DISPLAY)', file=sys.stderr)
        return False

    try:
        subprocess.run(cmd, input=value.encode(), check=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f'ssh-concierge: clipboard copy failed: {exc}', file=sys.stderr)
        return False


def main() -> None:
    """Wrapper entry point — called as ssh or scp via symlink."""
    tool = Path(sys.argv[0]).name

    real_binary = find_real_binary(tool)
    if real_binary is None:
        print(f'ssh-concierge: cannot find real {tool} in PATH', file=sys.stderr)
        sys.exit(1)

    args = sys.argv[1:]

    # Extract host based on tool type
    if tool == 'scp':
        host = extract_scp_host(args)
    else:
        host = extract_ssh_host(args)

    if host:
        runtime_dir = _default_runtime_dir()
        entry = lookup_hostdata(host, runtime_dir / 'hostdata.json')
        if entry:
            refs = entry.get('refs', {})
            resolved = _resolve_refs(refs) if refs else {}

            # Clipboard: resolve template and copy
            if resolved is not None and entry.get('clipboard'):
                clipboard_text = resolve_clipboard(entry['clipboard'], resolved)
                copy_to_clipboard(clipboard_text)

            # Password: askpass injection
            if resolved and resolved.get('password'):
                rc = _run_with_askpass(real_binary, tool, args, resolved['password'])
                sys.exit(rc)

    # Fallback: exec real binary with original args
    os.execv(real_binary, [tool, *args])


def _run_with_askpass(
    real_binary: str,
    tool: str,
    args: list[str],
    password: str,
) -> int:
    """Run the real binary with SSH_ASKPASS for password injection.

    Uses subprocess.run (not exec) so the askpass temp script gets cleaned up.
    SSH_ASKPASS_REQUIRE=force makes SSH use ASKPASS even with a TTY present,
    so we don't need setsid (which would break PTY allocation).
    """
    with askpass_env(password) as env_vars:
        env = {**os.environ, **env_vars}
        result = subprocess.run(
            [real_binary, *args],
            env=env,
        )
        return result.returncode
