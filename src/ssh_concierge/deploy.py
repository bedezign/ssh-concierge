"""Deploy SSH public keys to remote hosts via ssh-copy-id."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from ssh_concierge.config import _safe_filename
from ssh_concierge.expand import expand_host_config
from ssh_concierge.models import HostConfig
from ssh_concierge.onepassword import OnePassword, parse_item_to_host_configs
from ssh_concierge.password import ItemMeta, askpass_env, resolve_password


def fetch_all_hosts(op: OnePassword) -> list[tuple[HostConfig, ItemMeta]]:
    """Query 1Password and return all expanded HostConfigs with item metadata."""
    results: list[tuple[HostConfig, ItemMeta]] = []
    for item_id in op.list_managed_item_ids():
        item = op.get_item(item_id)
        meta = ItemMeta(
            vault_id=item.get('vault', {}).get('id', ''),
            item_id=item.get('id', ''),
        )
        for host in parse_item_to_host_configs(item):
            for expanded in expand_host_config(host):
                results.append((expanded, meta))
    return results


def resolve_host(
    alias: str,
    hosts: list[tuple[HostConfig, ItemMeta]],
) -> tuple[HostConfig, ItemMeta] | None:
    """Find a HostConfig whose aliases contain the given alias."""
    for host, meta in hosts:
        if alias in host.aliases:
            return host, meta
    return None


def find_siblings(
    host: HostConfig,
    hosts: list[tuple[HostConfig, ItemMeta]],
) -> list[tuple[HostConfig, ItemMeta]]:
    """Find sibling hosts: same section_label and fingerprint, excluding wildcards."""
    siblings = []
    for candidate, meta in hosts:
        if candidate is host:
            continue
        if (
            candidate.section_label == host.section_label
            and candidate.fingerprint == host.fingerprint
            and not any('*' in a or '?' in a for a in candidate.aliases)
        ):
            siblings.append((candidate, meta))
    return siblings


def _build_ssh_copy_id_args(host: HostConfig, key_path: Path) -> list[str]:
    """Build the ssh-copy-id command arguments for a host."""
    args = ['ssh-copy-id', '-i', str(key_path)]
    if host.port:
        args.extend(['-p', host.port.raw])
    target = host.aliases[0]
    if host.user:
        target = f'{host.user.raw}@{target}'
    args.append(target)
    return args


def deploy_key_to_host(
    host: HostConfig,
    key_path: Path,
    password: str | None = None,
) -> bool:
    """Deploy a public key to a host using ssh-copy-id.

    Returns True on success, False on failure.
    If password is provided, uses SSH_ASKPASS to automate authentication.
    Otherwise inherits stdin for interactive password prompts.
    """
    args = _build_ssh_copy_id_args(host, key_path)
    print(f'Deploying key to {host.aliases[0]}...')
    try:
        if password:
            with askpass_env(password) as env_vars:
                env = {**os.environ, **env_vars}
                # setsid detaches from TTY so SSH uses ASKPASS instead of stdin
                result = subprocess.run(
                    ['setsid'] + args,
                    env=env,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                )
        else:
            result = subprocess.run(
                args,
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stderr,
            )
    except FileNotFoundError:
        print('Error: ssh-copy-id not found. Install openssh-client.', file=sys.stderr)
        return False
    return result.returncode == 0


def _ensure_key_file(host: HostConfig, runtime_dir: Path) -> Path | None:
    """Get the public key file path, generating runtime config if needed."""
    if not host.fingerprint or not host.public_key:
        print(f'Error: no SSH key associated with {host.aliases[0]}', file=sys.stderr)
        return None

    key_path = runtime_dir / 'keys' / f'{_safe_filename(host.fingerprint)}.pub'
    if not key_path.exists():
        # Generate runtime config to create key files
        from ssh_concierge.cli import cmd_generate

        cmd_generate(runtime_dir)
    if not key_path.exists():
        print(f'Error: key file not found at {key_path}', file=sys.stderr)
        return None
    return key_path


def cmd_deploy_key(alias: str, all_siblings: bool, runtime_dir: Path) -> None:
    """Deploy SSH key to a host (and optionally its siblings)."""
    op = OnePassword()
    hosts = fetch_all_hosts(op)

    match = resolve_host(alias, hosts)
    if match is None:
        print(f'Error: alias {alias!r} not found in 1Password', file=sys.stderr)
        sys.exit(1)

    host, item_meta = match

    key_path = _ensure_key_file(host, runtime_dir)
    if key_path is None:
        sys.exit(1)

    # Resolve password once for all targets (siblings share the same item)
    raw_pw = host.password.raw if host.password else None
    resolved_pw = resolve_password(raw_pw, op, item_meta)

    targets: list[HostConfig] = [host]
    if all_siblings:
        siblings = find_siblings(host, hosts)
        sibling_hosts = [s for s, _ in siblings]
        targets.extend(sibling_hosts)
        if sibling_hosts:
            names = ', '.join(s.aliases[0] for s in sibling_hosts)
            print(f'Including siblings: {names}')

    failed: list[str] = []
    for target in targets:
        if not deploy_key_to_host(target, key_path, password=resolved_pw):
            failed.append(target.aliases[0])

    if failed:
        print(f'\nFailed: {", ".join(failed)}', file=sys.stderr)
        sys.exit(1)
