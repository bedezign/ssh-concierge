"""CLI for ssh-concierge: generate, flush, list, status."""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import itertools
import json
import os
import re
import shutil
import socket
import sys
import time
from pathlib import Path

from ssh_concierge.config import generate_runtime_config
from ssh_concierge.deploy import cmd_deploy_key
from ssh_concierge.expand import expand_host_config
from ssh_concierge.field import FieldValue, normalize_original, resolve_chain
from ssh_concierge.models import HostConfig
from ssh_concierge.onepassword import OnePassword, parse_item_to_host_configs
from ssh_concierge.opref import OpRef
from ssh_concierge.password import ItemMeta
from ssh_concierge.settings import Settings, load_settings
from ssh_concierge.wrap import lookup_hostdata


def _write_env_sh(settings: Settings) -> None:
    """Write env.sh in the runtime dir for the shell entry point to source.

    Keeps the hot path Python-free: the shell script reads these values
    instead of invoking ``ssh-concierge-py --config`` on every connection.
    """
    env_path = settings.runtime_dir / 'env.sh'
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(
        f"CONFIG='{settings.hosts_file}'\n"
        f"TTL='{settings.ttl}'\n"
    )


def _warn_noexec_askpass(askpass_dir: Path) -> None:
    """Warn if the askpass directory is on a noexec-mounted filesystem."""
    try:
        # Check the directory itself, or its parent if it doesn't exist yet
        check_path = askpass_dir
        while not check_path.exists():
            check_path = check_path.parent
        stat_result = os.statvfs(check_path)
        if stat_result.f_flag & os.ST_NOEXEC:
            print(
                f'WARNING: askpass directory {askpass_dir} is on a noexec filesystem.\n'
                f'  Password injection will fail. Set askpass_dir in your config file\n'
                f'  to a path on an executable filesystem (e.g. $XDG_RUNTIME_DIR).',
                file=sys.stderr,
            )
    except OSError:
        pass  # Can't check — don't block generation


def resolve_host_fields(
    host: HostConfig,
    meta: ItemMeta,
    cached_fields: dict[str, FieldValue] | None,
    op: OnePassword,
    *,
    no_cache: bool = False,
) -> HostConfig:
    """Resolve all FieldValues on a HostConfig, returning a new HostConfig.

    For each FieldValue:
    - Normalize self-refs (op://./field → op://vault/item/field)
    - Check cache (skip resolution if original unchanged)
    - Resolve non-sensitive references via op.read()
    - Sensitive fields stay unresolved (resolved at SSH time)
    """

    def _resolve_field(name: str, fv: FieldValue) -> FieldValue:
        try:
            return _resolve_field_inner(name, fv)
        except ValueError as exc:
            print(
                f'ssh-concierge: bad reference in field "{name}" '
                f'on item {meta.display_name}: {exc}',
                file=sys.stderr,
            )
            return fv

    def _resolve_field_inner(name: str, fv: FieldValue) -> FieldValue:
        # Normalize self-refs so the wrapper can resolve without item metadata
        normalized = normalize_original(fv.original, meta.vault_id, meta.item_id)
        if normalized != fv.original:
            fv = dataclasses.replace(fv, original=normalized)

        if fv.sensitive:
            return fv  # Don't resolve at generation time

        cached = cached_fields.get(name) if cached_fields and not no_cache else None
        if not fv.needs_resolution(cached):
            # Original unchanged — but the target value may have changed.
            # Check if the resolved value is still current (cache-only, no CLI calls).
            if cached and cached.field_type == 'reference':  # type: ignore[union-attr]
                fresh = resolve_chain(fv.original, op, cache_only=True)
                if fresh is not None and fresh != cached.resolved:  # type: ignore[union-attr]
                    return fv.resolve(op, vault_id=meta.vault_id, item_id=meta.item_id)
            return cached  # type: ignore[return-value]

        return fv.resolve(op, vault_id=meta.vault_id, item_id=meta.item_id)

    def _resolve_optional(name: str, fv: FieldValue | None) -> FieldValue | None:
        return _resolve_field(name, fv) if fv else None

    return dataclasses.replace(
        host,
        hostname=_resolve_optional('hostname', host.hostname),
        port=_resolve_optional('port', host.port),
        user=_resolve_optional('user', host.user),
        password=_resolve_optional('password', host.password),
        otp=_resolve_optional('otp', host.otp),
        extra_directives={k: _resolve_field(k, fv) for k, fv in host.extra_directives.items()},
        custom_fields={k: _resolve_field(k, fv) for k, fv in host.custom_fields.items()},
    )


def _build_hostdata_entry(host: HostConfig) -> dict | None:
    """Build a hostdata entry from a resolved HostConfig.

    Iterates all FieldValues already on the HostConfig and serializes them.
    Returns None if the host has no fields worth storing.
    """
    fields = {name: fv.to_hostdata() for name, fv in _iter_host_fields(host)}

    entry: dict = {}
    if host.host_filter:
        entry['on'] = host.host_filter
    if host.clipboard:
        entry['clipboard'] = host.clipboard
    if host.key_ref:
        entry['key'] = host.key_ref
    if host.password_prompt:
        entry['password_prompt'] = host.password_prompt
    if host.otp_prompt:
        entry['otp_prompt'] = host.otp_prompt
    if fields:
        entry['fields'] = fields

    return entry or None


def _iter_host_fields(host: HostConfig):
    """Yield (name, FieldValue) for all resolvable fields on a HostConfig."""
    named = [
        ('password', host.password),
        ('otp', host.otp),
        ('hostname', host.hostname),
        ('port', host.port),
        ('user', host.user),
    ]
    scalar_fields = ((name, fv) for name, fv in named if fv is not None)
    dict_fields = itertools.chain(host.extra_directives.items(), host.custom_fields.items())
    yield from itertools.chain(scalar_fields, dict_fields)


def _load_cached_hostdata(runtime_dir: Path) -> dict[str, dict[str, FieldValue]]:
    """Load cached field data from the existing host data cache.

    Returns {alias: {field_name: FieldValue}}.
    """
    hd_path = runtime_dir / 'hostdata.json'
    if not hd_path.is_file():
        return {}
    try:
        data = json.loads(hd_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}

    return {
        alias: {
            name: FieldValue.from_hostdata(fdata, name)
            for name, fdata in entry.get('fields', {}).items()
        }
        for alias, entry in data.items()
        if entry.get('fields')
    }


def _parse_op_item_ref(ref: str) -> tuple[str, str]:
    """Parse an op://Vault/Item reference into (vault, title).

    Supports quoted names ("Item / Name") and URL-encoded slashes (%2F).
    """
    parsed = OpRef.parse(ref)
    return parsed.vault, parsed.item


def _extract_key_pair(item: dict) -> tuple[str, str] | None:
    """Extract (public_key, fingerprint) from top-level item fields, or None."""
    public_key = None
    fingerprint = None
    for f in item.get('fields', []):
        if f.get('section'):
            continue
        label = f.get('label')
        if label == 'public key':
            public_key = f.get('value')
        elif label == 'fingerprint':
            fingerprint = f.get('value')
    return (public_key, fingerprint) if public_key and fingerprint else None


def _build_key_registry(items: list[dict]) -> dict[tuple, tuple[str, str]]:
    """Build a registry of SSH key data from fetched items.

    Maps (vault_name.lower(), title.lower()) and (item_id,) → (public_key, fingerprint).
    """
    registry: dict[tuple, tuple[str, str]] = {}
    for item in items:
        key_pair = _extract_key_pair(item)
        if not key_pair:
            continue
        vault_name = item.get('vault', {}).get('name', '')
        title = item.get('title', '')
        item_id = item.get('id', '')
        if vault_name and title:
            registry[(vault_name.lower(), title.lower())] = key_pair
        if item_id:
            registry[(item_id,)] = key_pair
    return registry


def _resolve_key_ref(
    host: HostConfig,
    key_registry: dict,
    op: OnePassword | None = None,
    meta: ItemMeta | None = None,
) -> HostConfig:
    """Resolve a key_ref on a HostConfig against the key registry.

    If key_ref is an op:// reference (e.g. op://./SSH Config/key), resolves it
    via the seeded cache first (no CLI calls) to get the actual item identifier.
    Then looks up the resolved value in the key registry.

    If the host already has a public_key or has no key_ref, returns unchanged.
    """
    if not host.key_ref or host.public_key:
        return host

    aliases = ', '.join(host.aliases)
    key_ref = host.key_ref

    # Resolve self-references (op://./...) via seeded cache (no CLI calls)
    if '://' in key_ref and op is not None:
        ref = OpRef.parse(key_ref)
        if ref.is_self_ref:
            if not meta:
                print(f'ssh-concierge: cannot resolve self-ref "{key_ref}" without item metadata (host {aliases})', file=sys.stderr)
                return host
            resolved = op.read(ref.normalized(meta.vault_id, meta.item_id).for_op(), cache_only=True)
            if not resolved:
                print(f'ssh-concierge: key reference "{key_ref}" could not be resolved (host {aliases})', file=sys.stderr)
                return host
            key_ref = resolved

    try:
        vault, title = _parse_op_item_ref(key_ref)
    except ValueError:
        print(f'ssh-concierge: invalid key reference "{key_ref}" on host {aliases}', file=sys.stderr)
        return host

    key = key_registry.get((vault.lower(), title.lower()))
    if not key:
        print(f'ssh-concierge: key "{key_ref}" not found (host {aliases})', file=sys.stderr)
        return host

    return dataclasses.replace(host, public_key=key[0], fingerprint=key[1])


def cmd_generate(
    settings: Settings,
    *,
    quiet: bool = False,
    no_cache: bool = False,
) -> None:
    """Query 1Password and regenerate the runtime config."""
    runtime_dir = settings.runtime_dir
    runtime_dir.mkdir(parents=True, exist_ok=True)
    lock_path = runtime_dir / ".lock"

    with open(lock_path, "w") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # Another process holds the lock — check if config is now fresh
            conf = settings.hosts_file
            if conf.exists():
                age = time.time() - conf.stat().st_mtime
                if age < settings.ttl:
                    if not quiet:
                        print("Config is fresh (generated by another process)")
                    return  # Another process just regenerated
            # Wait for lock (blocking)
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            # Double-check after acquiring lock
            if conf.exists():
                age = time.time() - conf.stat().st_mtime
                if age < settings.ttl:
                    if not quiet:
                        print("Config is fresh (generated by another process)")
                    return

        if not quiet:
            print("Querying 1Password...")

        op = OnePassword(op_timeout=settings.op_timeout)

        # Load cached hostdata for cache comparison
        cached_hostdata = _load_cached_hostdata(runtime_dir) if not no_cache else {}

        item_ids = op.list_managed_item_ids()
        hosts = []
        hostdata: dict[str, dict] = {}
        items_processed = 0

        # First pass: fetch all items, parse into HostConfigs, build key registry
        raw_items: list[dict] = []
        parsed: list[tuple[HostConfig, ItemMeta]] = []
        for item_id in item_ids:
            item = op.get_item(item_id)
            items_processed += 1
            raw_items.append(item)
            vault = item.get('vault', {})
            meta = ItemMeta(
                vault_id=vault.get('id', ''),
                item_id=item.get('id', ''),
                vault_name=vault.get('name', ''),
                item_title=item.get('title', ''),
            )
            for host in parse_item_to_host_configs(item):
                parsed.append((host, meta))

        key_registry = _build_key_registry(raw_items)
        op.seed_from_items(raw_items)

        # Filter by local hostname
        local_hostname = socket.gethostname()
        parsed = [(h, m) for h, m in parsed if h.matches_host(local_hostname)]

        # Second pass: resolve key refs, expand, resolve fields, generate
        for host, meta in parsed:
            host = _resolve_key_ref(host, key_registry, op, meta)
            for expanded in expand_host_config(host):
                # Use first non-wildcard alias for cache lookup
                cache_alias = next(
                    (a for a in expanded.aliases if '*' not in a and '?' not in a),
                    None,
                )
                cached_fields = cached_hostdata.get(cache_alias) if cache_alias else None
                resolved_host = resolve_host_fields(
                    expanded, meta, cached_fields, op, no_cache=no_cache,
                )
                hosts.append(resolved_host)
                entry = _build_hostdata_entry(resolved_host)
                if entry:
                    for alias in resolved_host.aliases:
                        if '*' not in alias and '?' not in alias:
                            hostdata[alias] = entry

        generate_runtime_config(hosts, runtime_dir, hostdata or None)
        _write_env_sh(settings)

        password_count = sum(
            1 for e in hostdata.values()
            if any(f.get('sensitive') for f in e.get('fields', {}).values())
        )
        clipboard_count = sum(1 for e in hostdata.values() if 'clipboard' in e)
        if not quiet:
            print(
                f"Generated: {len(hosts)} hosts from {items_processed} items"
                f" ({password_count} password, {clipboard_count} clipboard)"
            )
            print(f"Config:    {runtime_dir / 'hosts.conf'}")
            if hostdata:
                print(f"Hostdata:  {runtime_dir / 'hostdata.json'}")

        if password_count > 0:
            _warn_noexec_askpass(settings.askpass_dir)


def cmd_flush(settings: Settings, *, quiet: bool = False) -> None:
    """Remove the runtime config directory."""
    if settings.runtime_dir.exists():
        shutil.rmtree(settings.runtime_dir)
        if not quiet:
            print(f"Removed {settings.runtime_dir}")
    elif not quiet:
        print("Nothing to flush (no runtime config)")


def cmd_status(settings: Settings) -> None:
    """Show config age, managed host count, staleness."""
    conf = settings.hosts_file
    if not conf.exists():
        print("No config generated yet. Run: ssh-concierge --generate")
        return

    age_secs = time.time() - conf.stat().st_mtime
    content = conf.read_text()
    host_count = len(re.findall(r"^Host ", content, re.MULTILINE))

    age_min = int(age_secs // 60)
    stale = age_secs >= settings.ttl
    status = "STALE" if stale else "fresh"

    print(f"Config: {conf}")
    print(f"Status: {status} (age: {age_min}m)")
    print(f"Managed hosts: {host_count}")


def cmd_debug(alias: str, settings: Settings) -> None:
    """Show the generated config block for a given alias."""
    runtime_dir = settings.runtime_dir
    conf = settings.hosts_file
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
    entry = lookup_hostdata(alias, runtime_dir / 'hostdata.json')
    if entry:
        # Host filter
        on_filter = entry.get('on')
        if on_filter:
            print(f'    # On: {on_filter}')

        # Key reference
        key = entry.get('key')
        has_identity = any('IdentityFile' in line for line in block_lines)
        if key:
            if has_identity:
                print(f'    # Key: {key}')
            else:
                print(f'    # Key: {key}  ⚠ NOT RESOLVED (no IdentityFile generated)')

        # All fields with resolution status
        fields = entry.get('fields', {})
        if fields:
            print('    # Fields:')
            for name, fdata in fields.items():
                original = fdata.get('original', '?')
                resolved = fdata.get('resolved')
                sensitive = fdata.get('sensitive', False)
                if sensitive:
                    print(f'    #   {name}: {original}  (sensitive, resolved at SSH time)')
                elif resolved is not None and resolved != original:
                    print(f'    #   {name}: {original} → {resolved}')
                elif resolved is not None:
                    print(f'    #   {name}: {original}')
                else:
                    print(f'    #   {name}: {original}  ⚠ UNRESOLVED')

        # Prompt overrides
        pw_prompt = entry.get('password_prompt')
        if pw_prompt:
            print(f'    # Password prompt: {pw_prompt}')
        otp_prompt = entry.get('otp_prompt')
        if otp_prompt:
            print(f'    # OTP prompt: {otp_prompt}')

        # Clipboard
        clipboard = entry.get('clipboard')
        if clipboard:
            print(f'    # Clipboard: {clipboard!r}')

    # Config age
    age_secs = time.time() - conf.stat().st_mtime
    age_min = int(age_secs // 60)
    stale = age_secs >= settings.ttl
    status = 'STALE' if stale else 'fresh'
    print(f'\nConfig age: {age_min}m ({status})')


def cmd_list(settings: Settings) -> None:
    """List all managed hosts from the generated config."""
    conf = settings.hosts_file
    if not conf.exists():
        print("No config generated yet. Run: ssh-concierge --generate")
        return

    content = conf.read_text()
    for match in re.finditer(r"^Host (.+)$", content, re.MULTILINE):
        aliases = match.group(1)
        print(aliases)


def cmd_config(directive: str | None, settings: Settings) -> None:
    """Show configuration directives and their values."""
    if directive:
        try:
            print(settings.get(directive))
        except KeyError:
            print(f'unknown directive: {directive}', file=sys.stderr)
            print(f'available: {", ".join(Settings.DIRECTIVES)}', file=sys.stderr)
            sys.exit(1)
    else:
        for name in Settings.DIRECTIVES:
            print(f'{name}={settings.get(name)}')


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
    group.add_argument("--config", nargs="?", const="", metavar="DIRECTIVE", help="Show config value (or all if no directive given)")

    parser.add_argument("--all", action="store_true", help="Deploy to all sibling hosts (only with --deploy-key)")
    parser.add_argument("--no-cache", action="store_true", help="Force re-resolution of all field references")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress informational output")

    args = parser.parse_args()

    if args.all and not args.deploy_key:
        parser.error("--all can only be used with --deploy-key")

    if args.no_cache and not args.generate:
        parser.error("--no-cache can only be used with --generate")

    settings = load_settings()

    if args.config is not None:
        cmd_config(args.config or None, settings)
    elif args.generate:
        cmd_generate(settings, quiet=args.quiet, no_cache=args.no_cache)
    elif args.flush:
        cmd_flush(settings, quiet=args.quiet)
    elif args.list:
        cmd_list(settings)
    elif args.status:
        cmd_status(settings)
    elif args.debug:
        cmd_debug(args.debug, settings)
    elif args.deploy_key:
        cmd_deploy_key(args.deploy_key, args.all, settings.runtime_dir)
