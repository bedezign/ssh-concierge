"""SSH/SCP wrapper with transparent password injection from 1Password."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

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


def lookup_reference(host: str, passwords_path: Path) -> str | None:
    """Look up an op:// reference for a host in passwords.json."""
    if not passwords_path.is_file():
        return None
    try:
        data = json.loads(passwords_path.read_text())
        return data.get(host)
    except (json.JSONDecodeError, OSError):
        return None


def resolve_via_op_read(reference: str) -> str | None:
    """Resolve an op:// reference to a plaintext password via `op read`."""
    from ssh_concierge.onepassword import OpError, _run_op

    try:
        return _run_op(['read', reference]).strip()
    except OpError as exc:
        print(f'ssh-concierge: password resolution failed: {exc}', file=sys.stderr)
        return None


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
        ref = lookup_reference(host, runtime_dir / 'passwords.json')
        if ref:
            password = resolve_via_op_read(ref)
            if password:
                rc = _run_with_askpass(real_binary, tool, args, password)
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
