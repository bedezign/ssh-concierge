"""CLI for ssh-concierge: generate, flush, list, status."""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import json
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
from ssh_concierge.field import FieldValue, normalize_original
from ssh_concierge.models import HostConfig
from ssh_concierge.password import ItemMeta


def _build_op_read_cache(raw_items: list[dict]) -> dict[str, str]:
    """Build an in-memory cache of op:// reference → value from fetched items.

    Indexes every field from every fetched item so that resolve_single() can
    do a dict lookup instead of calling `op read` for references we already have.

    Keys are lowercased op://{vault_id}/{item_id}/{field_label} for item-level
    fields and op://{vault_id}/{item_id}/{section_label}/{field_label} for
    section fields. The `op` CLI does case-insensitive field name matching,
    so we mirror that by lowercasing keys and looking up with lowercased refs.
    """
    cache: dict[str, str] = {}
    for item in raw_items:
        vault_id = item.get('vault', {}).get('id', '')
        item_id = item.get('id', '')
        if not vault_id or not item_id:
            continue
        prefix = f'op://{vault_id}/{item_id}'
        for field in item.get('fields', []):
            value = field.get('value', '')
            if not value:
                continue
            label = field.get('label', '')
            if not label:
                continue
            section = field.get('section')
            if section:
                section_label = section.get('label', '')
                if section_label:
                    cache[f'{prefix}/{section_label}/{label}'.lower()] = value
            else:
                cache[f'{prefix}/{label}'.lower()] = value
    return cache


def _build_hostdata_entry(
    host: HostConfig,
    meta: ItemMeta,
    cached_fields: dict[str, FieldValue] | None,
    *,
    no_cache: bool = False,
    op_read_cache: dict[str, str] | None = None,
) -> dict | None:
    """Build a hostdata entry for a host using FieldValue resolution.

    Returns None if the host has no fields worth storing.
    """
    entry: dict = {}
    fields: dict[str, FieldValue] = {}

    # Collect all raw fields from the host
    raw_fields: dict[str, str] = {}
    if host.password:
        raw_fields['password'] = host.password
    if host.hostname:
        raw_fields['hostname'] = host.hostname
    if host.user:
        raw_fields['user'] = host.user
    if host.port:
        raw_fields['port'] = host.port

    # Include extra directive fields that have op:// or ops:// references
    for directive, value in host.extra_directives.items():
        if '://' in value:
            raw_fields[directive] = value

    # Also include fields referenced in clipboard template
    if host.clipboard and host.section_label:
        entry['clipboard'] = host.clipboard
        for field_name in re.findall(r'\{(\w+)\}', host.clipboard):
            if field_name not in raw_fields:
                field_val = _get_host_field(host, field_name)
                if field_val:
                    raw_fields[field_name] = field_val

    if host.key_ref:
        entry['key'] = host.key_ref

    # Create FieldValues, check cache, resolve non-sensitive
    for name, raw in raw_fields.items():
        # Normalize self-refs so the wrapper can resolve without item metadata
        raw = normalize_original(raw, meta.vault_id, meta.item_id)
        fv = FieldValue.from_raw(raw, name)
        cached = cached_fields.get(name) if cached_fields and not no_cache else None

        if fv.sensitive:
            # Sensitive: store raw, never resolve at gen time
            # But normalize the reference for storage
            fields[name] = fv
        elif not fv.needs_resolution(cached):
            # Cache hit: reuse cached resolved value
            fields[name] = cached  # type: ignore[assignment]
        else:
            # Resolve now
            fields[name] = fv.resolve(
                vault_id=meta.vault_id,
                item_id=meta.item_id,
                op_read_cache=op_read_cache,
            )

    if fields:
        entry['fields'] = {name: fv.to_hostdata() for name, fv in fields.items()}

    return entry or None


def _get_host_field(host: HostConfig, name: str) -> str | None:
    """Look up a HostConfig attribute by field name (case-insensitive)."""
    result = {
        'password': host.password,
        'user': host.user,
        'port': host.port,
        'hostname': host.hostname,
    }.get(name.lower())
    if result:
        return result
    # Case-insensitive lookup in custom fields
    name_lower = name.lower()
    for k, v in host.custom_fields.items():
        if k.lower() == name_lower:
            return v
    return None


def _load_cached_hostdata(runtime_dir: Path) -> dict[str, dict[str, FieldValue]]:
    """Load cached field data from existing hostdata.json.

    Returns {alias: {field_name: FieldValue}}.
    """
    hd_path = runtime_dir / 'hostdata.json'
    if not hd_path.is_file():
        return {}
    try:
        data = json.loads(hd_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}

    result: dict[str, dict[str, FieldValue]] = {}
    for alias, entry in data.items():
        fields_data = entry.get('fields', {})
        if fields_data:
            result[alias] = {
                name: FieldValue.from_hostdata(fdata, name)
                for name, fdata in fields_data.items()
            }
    return result


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


def cmd_generate(
    runtime_dir: Path,
    *,
    quiet: bool = False,
    no_cache: bool = False,
) -> None:
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

        # Load cached hostdata for cache comparison
        cached_hostdata = _load_cached_hostdata(runtime_dir) if not no_cache else {}

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
        op_read_cache = _build_op_read_cache(raw_items)

        # Second pass: resolve key refs, expand, generate
        for host, meta in parsed:
            host = _resolve_key_ref(host, key_registry)
            for expanded in expand_host_config(host):
                hosts.append(expanded)
                # Use first non-wildcard alias for cache lookup
                cache_alias = next(
                    (a for a in expanded.aliases if '*' not in a and '?' not in a),
                    None,
                )
                cached_fields = cached_hostdata.get(cache_alias) if cache_alias else None
                entry = _build_hostdata_entry(
                    expanded, meta, cached_fields,
                    no_cache=no_cache, op_read_cache=op_read_cache,
                )
                if entry:
                    for alias in expanded.aliases:
                        if '*' not in alias and '?' not in alias:
                            hostdata[alias] = entry

        generate_runtime_config(hosts, runtime_dir, hostdata or None)

        password_count = sum(
            1 for e in hostdata.values()
            if any(
                f.get('sensitive')
                for f in e.get('fields', {}).values()
            )
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

        fields = entry.get('fields', {})
        # Show password info
        pw_field = fields.get('password', {})
        if pw_field:
            print(f'    # Password: {pw_field.get("original", "?")}')

        clipboard = entry.get('clipboard')
        if clipboard:
            print(f'    # Clipboard: {clipboard!r}')
            for name, fdata in fields.items():
                if name != 'password':
                    print(f'    #   {name}: {fdata.get("original", "?")}')

        # Legacy format support
        refs = entry.get('refs', {})
        if refs and not fields:
            if 'password' in refs:
                print(f'    # Password: {refs["password"]}')
            if clipboard:
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
    parser.add_argument("--no-cache", action="store_true", help="Force re-resolution of all field references")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress informational output")

    args = parser.parse_args()

    if args.all and not args.deploy_key:
        parser.error("--all can only be used with --deploy-key")

    if args.no_cache and not args.generate:
        parser.error("--no-cache can only be used with --generate")

    runtime_dir = _default_runtime_dir()

    if args.generate:
        cmd_generate(runtime_dir, quiet=args.quiet, no_cache=args.no_cache)
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
