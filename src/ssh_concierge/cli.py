"""CLI for ssh-concierge: generate, flush, list, status."""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import os
import re
import shutil
import sys
import time
from pathlib import Path

from ssh_concierge import onepassword
from ssh_concierge.config import generate_runtime_config
from ssh_concierge.deploy import cmd_deploy_key
from ssh_concierge.expand import expand_host_config
from ssh_concierge.models import HostConfig
from ssh_concierge.password import ItemMeta, build_op_reference


def _build_hostdata_entry(host: HostConfig, meta: ItemMeta) -> dict | None:
    """Build a hostdata entry for a host (refs + clipboard template).

    Returns None if the host has neither password nor clipboard.
    """
    entry: dict = {}
    refs: dict[str, str] = {}

    if host.password and host.section_label:
        refs['password'] = build_op_reference(host.password, meta, host.section_label)

    if host.clipboard and host.section_label:
        entry['clipboard'] = host.clipboard
        for field_name in re.findall(r'\{(\w+)\}', host.clipboard):
            if field_name not in refs:
                field_val = _get_host_field(host, field_name)
                if field_val:
                    refs[field_name] = _to_ref_or_literal(
                        field_val, meta, host.section_label,
                    )

    if host.key_ref:
        entry['key'] = host.key_ref

    if refs:
        entry['refs'] = refs
    return entry or None


def _get_host_field(host: HostConfig, name: str) -> str | None:
    """Look up a HostConfig attribute by field name."""
    return {
        'password': host.password,
        'user': host.user,
        'port': host.port,
        'hostname': host.hostname,
    }.get(name)


def _to_ref_or_literal(
    value: str, meta: ItemMeta, section_label: str,
) -> str:
    """Convert a field value to an op:// reference or keep as literal."""
    if value.startswith('op://'):
        return build_op_reference(value, meta, section_label)
    return value


def _parse_op_item_ref(ref: str) -> tuple[str, str]:
    """Parse an op://Vault/Item reference into (vault, title).

    Strips the op:// prefix and splits on the first slash.
    """
    path = ref.removeprefix('op://')
    parts = path.split('/', 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f'Invalid op:// item reference: {ref}')
    return parts[0], parts[1]


def _build_key_registry(
    items: list[dict],
) -> dict[tuple[str, str], tuple[str, str]]:
    """Build a registry of SSH key data from fetched items.

    Returns a dict mapping (vault_name.lower(), title.lower()) and
    (item_id,) → (public_key, fingerprint).
    """
    registry: dict = {}
    for item in items:
        fields = item.get('fields', [])
        public_key = None
        fingerprint = None
        for field in fields:
            if field.get('section'):
                continue
            if field.get('label') == 'public key':
                public_key = field.get('value')
            elif field.get('label') == 'fingerprint':
                fingerprint = field.get('value')
        if public_key and fingerprint:
            vault_name = item.get('vault', {}).get('name', '')
            title = item.get('title', '')
            if vault_name and title:
                registry[(vault_name.lower(), title.lower())] = (public_key, fingerprint)
            item_id = item.get('id', '')
            if item_id:
                registry[(item_id,)] = (public_key, fingerprint)
    return registry


def _resolve_key_ref(
    host: HostConfig,
    key_registry: dict,
) -> HostConfig:
    """Resolve a key_ref on a HostConfig against the key registry.

    If the host already has a public_key or has no key_ref, returns unchanged.
    """
    if not host.key_ref or host.public_key:
        return host
    try:
        vault, title = _parse_op_item_ref(host.key_ref)
    except ValueError:
        print(
            f'ssh-concierge: invalid key reference "{host.key_ref}"',
            file=sys.stderr,
        )
        return host
    key = key_registry.get((vault.lower(), title.lower()))
    if not key:
        print(
            f'ssh-concierge: key "{host.key_ref}" not found',
            file=sys.stderr,
        )
        return host
    return dataclasses.replace(host, public_key=key[0], fingerprint=key[1])


def _default_runtime_dir() -> Path:
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "ssh-concierge"
    return Path("/tmp") / f"ssh-concierge-{os.getuid()}"


def cmd_generate(runtime_dir: Path, *, quiet: bool = False) -> None:
    """Query 1Password and regenerate the runtime config."""
    runtime_dir.mkdir(parents=True, exist_ok=True)
    lock_path = runtime_dir / ".lock"

    with open(lock_path, "w") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # Another process holds the lock — check if config is now fresh
            conf = runtime_dir / "hosts.conf"
            if conf.exists():
                age = time.time() - conf.stat().st_mtime
                if age < 3600:
                    if not quiet:
                        print("Config is fresh (generated by another process)")
                    return  # Another process just regenerated
            # Wait for lock (blocking)
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            # Double-check after acquiring lock
            if conf.exists():
                age = time.time() - conf.stat().st_mtime
                if age < 3600:
                    if not quiet:
                        print("Config is fresh (generated by another process)")
                    return

        if not quiet:
            print("Querying 1Password...")

        item_ids = onepassword.list_managed_item_ids()
        hosts = []
        hostdata: dict[str, dict] = {}
        items_processed = 0

        # First pass: fetch all items, parse into HostConfigs, build key registry
        raw_items: list[dict] = []
        parsed: list[tuple[HostConfig, ItemMeta]] = []
        for item_id in item_ids:
            item = onepassword.get_item(item_id)
            items_processed += 1
            raw_items.append(item)
            meta = ItemMeta(
                vault_id=item.get('vault', {}).get('id', ''),
                item_id=item.get('id', ''),
            )
            for host in onepassword.parse_item_to_host_configs(item):
                parsed.append((host, meta))

        key_registry = _build_key_registry(raw_items)

        # Second pass: resolve key refs, expand, generate
        for host, meta in parsed:
            host = _resolve_key_ref(host, key_registry)
            for expanded in expand_host_config(host):
                hosts.append(expanded)
                entry = _build_hostdata_entry(expanded, meta)
                if entry:
                    for alias in expanded.aliases:
                        if '*' not in alias and '?' not in alias:
                            hostdata[alias] = entry

        generate_runtime_config(hosts, runtime_dir, hostdata or None)

        password_count = sum(
            1 for e in hostdata.values() if 'password' in e.get('refs', {})
        )
        clipboard_count = sum(
            1 for e in hostdata.values() if 'clipboard' in e
        )
        if not quiet:
            print(
                f"Generated: {len(hosts)} hosts from {items_processed} items"
                f" ({password_count} password, {clipboard_count} clipboard)"
            )
            print(f"Config:    {runtime_dir / 'hosts.conf'}")
            if hostdata:
                print(f"Hostdata:  {runtime_dir / 'hostdata.json'}")


def cmd_flush(runtime_dir: Path, *, quiet: bool = False) -> None:
    """Remove the runtime config directory."""
    if runtime_dir.exists():
        shutil.rmtree(runtime_dir)
        if not quiet:
            print(f"Removed {runtime_dir}")
    elif not quiet:
        print("Nothing to flush (no runtime config)")


def cmd_status(runtime_dir: Path) -> None:
    """Show config age, managed host count, staleness."""
    conf = runtime_dir / "hosts.conf"
    if not conf.exists():
        print("No config generated yet. Run: ssh-concierge --generate")
        return

    age_secs = time.time() - conf.stat().st_mtime
    content = conf.read_text()
    host_count = len(re.findall(r"^Host ", content, re.MULTILINE))

    age_min = int(age_secs // 60)
    stale = age_secs >= 3600
    status = "STALE" if stale else "fresh"

    print(f"Config: {conf}")
    print(f"Status: {status} (age: {age_min}m)")
    print(f"Managed hosts: {host_count}")


def cmd_debug(alias: str, runtime_dir: Path) -> None:
    """Show the generated config block for a given alias."""
    conf = runtime_dir / 'hosts.conf'
    if not conf.exists():
        print('No config generated yet. Run: ssh-concierge --generate')
        return

    content = conf.read_text()
    lines = content.splitlines()

    # Find the Host block containing this alias
    block_start = None
    for i, line in enumerate(lines):
        if line.startswith('Host '):
            aliases_on_line = line[5:].split()
            if alias in aliases_on_line:
                block_start = i
                break

    if block_start is None:
        print(f'Alias "{alias}" not found in managed hosts.')
        return

    # Collect the block: Host line + indented lines until next Host or EOF
    block_lines = [lines[block_start]]
    for i in range(block_start + 1, len(lines)):
        if lines[i].startswith('Host '):
            break
        block_lines.append(lines[i])

    # Strip trailing blank lines
    while block_lines and not block_lines[-1].strip():
        block_lines.pop()

    # Print the block
    print('\n'.join(block_lines))

    # Look up hostdata
    from ssh_concierge.wrap import lookup_hostdata

    entry = lookup_hostdata(alias, runtime_dir / 'hostdata.json')
    if entry:
        key = entry.get('key')
        if key:
            print(f'    # Key: {key}')
        refs = entry.get('refs', {})
        if 'password' in refs:
            print(f'    # Password: {refs["password"]}')
        clipboard = entry.get('clipboard')
        if clipboard:
            print(f'    # Clipboard: {clipboard!r}')
            for name, ref in refs.items():
                if name != 'password':
                    print(f'    #   {name}: {ref}')

    # Config age
    age_secs = time.time() - conf.stat().st_mtime
    age_min = int(age_secs // 60)
    stale = age_secs >= 3600
    status = 'STALE' if stale else 'fresh'
    print(f'\nConfig age: {age_min}m ({status})')


def cmd_list(runtime_dir: Path) -> None:
    """List all managed hosts from the generated config."""
    conf = runtime_dir / "hosts.conf"
    if not conf.exists():
        print("No config generated yet. Run: ssh-concierge --generate")
        return

    content = conf.read_text()
    for match in re.finditer(r"^Host (.+)$", content, re.MULTILINE):
        aliases = match.group(1)
        print(aliases)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="ssh-concierge",
        description="Dynamic SSH configuration provider backed by 1Password",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate", action="store_true", help="Regenerate runtime config from 1Password")
    group.add_argument("--flush", action="store_true", help="Remove runtime config")
    group.add_argument("--list", action="store_true", help="List managed hosts")
    group.add_argument("--status", action="store_true", help="Show config status")
    group.add_argument("--debug", metavar="ALIAS", help="Show generated config for a host alias")
    group.add_argument("--deploy-key", metavar="ALIAS", help="Deploy SSH key to a host")

    parser.add_argument("--all", action="store_true", help="Deploy to all sibling hosts (only with --deploy-key)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress informational output")

    args = parser.parse_args()

    if args.all and not args.deploy_key:
        parser.error("--all can only be used with --deploy-key")

    runtime_dir = _default_runtime_dir()

    if args.generate:
        cmd_generate(runtime_dir, quiet=args.quiet)
    elif args.flush:
        cmd_flush(runtime_dir, quiet=args.quiet)
    elif args.list:
        cmd_list(runtime_dir)
    elif args.status:
        cmd_status(runtime_dir)
    elif args.debug:
        cmd_debug(args.debug, runtime_dir)
    elif args.deploy_key:
        cmd_deploy_key(args.deploy_key, args.all, runtime_dir)
