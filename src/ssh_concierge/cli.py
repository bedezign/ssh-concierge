"""CLI for ssh-concierge: generate, flush, list, status."""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from op_core import (
    CLIBackend,
    FieldValue,
    InMemoryBackend,
    Item,
    OnePassword,
    OpRef,
    normalize_original,
)

from ssh_concierge.config import generate_runtime_config
from ssh_concierge.deploy import cmd_deploy_key
from ssh_concierge.expand import expand_host_config
from ssh_concierge.models import HostConfig
from ssh_concierge.password import ItemMeta
from ssh_concierge.settings import Settings, load_settings
from ssh_concierge.ssh_items import (
    SSH_HOST_TAG,
    complete_field_refs,
    parse_item_to_host_configs,
)
from ssh_concierge.wrap import lookup_hostdata


def _write_env_sh(settings: Settings) -> None:
    """Write env.sh for the shell entry point to source.

    Keeps the hot path Python-free: the shell script reads these values
    instead of invoking ``ssh-concierge-py --config`` on every connection.

    Written next to the config file if one exists (preferred — survives
    reboots), otherwise in runtime_dir as fallback.
    """
    content = f"CONFIG='{settings.hosts_file}'\nTTL='{settings.ttl}'\n"

    if settings.config_file:
        config_env = settings.config_file.parent / "env.sh"
        config_env.write_text(content)
    else:
        settings.env_file.parent.mkdir(parents=True, exist_ok=True)
        settings.env_file.write_text(content)


def _warn_noexec_askpass(askpass_dir: Path) -> None:
    """Warn if the askpass directory is on a noexec-mounted filesystem."""
    if not hasattr(os, "ST_NOEXEC"):
        return  # os.ST_NOEXEC is Linux-only; skip on macOS/other platforms
    try:
        # Check the directory itself, or its parent if it doesn't exist yet
        check_path = askpass_dir
        while not check_path.exists():
            check_path = check_path.parent
        stat_result = os.statvfs(check_path)
        if stat_result.f_flag & os.ST_NOEXEC:
            print(
                f"WARNING: askpass directory {askpass_dir} is on a noexec filesystem.\n"
                f"  Password injection will fail. Set askpass_dir in your config file\n"
                f"  to a path on an executable filesystem (e.g. $XDG_RUNTIME_DIR).",
                file=sys.stderr,
            )
    except OSError:
        pass  # Can't check — don't block generation


class AgentQueryError(Exception):
    """Raised when the SSH agent cannot be queried for fingerprints."""


def _get_agent_fingerprints() -> set[str]:
    """Query the SSH agent for available key fingerprints.

    Returns a set of fingerprint strings (e.g. 'SHA256:abc...').
    Raises AgentQueryError if the agent is unavailable or cannot be queried.
    """
    if not os.environ.get("SSH_AUTH_SOCK"):
        raise AgentQueryError("SSH_AUTH_SOCK not set")

    try:
        result = subprocess.run(
            ["ssh-add", "-l"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        raise AgentQueryError("ssh-add not found")
    except subprocess.TimeoutExpired:
        raise AgentQueryError("ssh-add timed out")
    except OSError as exc:
        raise AgentQueryError(f"ssh-add failed: {exc}")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise AgentQueryError(
            f"ssh-add exited {result.returncode}{': ' + stderr if stderr else ''}"
        )

    # Format: "bits fingerprint comment (type)"
    fingerprints = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            fingerprints.add(parts[1])
    return fingerprints


def _warn_missing_agent_keys(
    hosts: list[HostConfig],
    hostdata: dict[str, dict],
) -> None:
    """Warn about exported keys that are not available in the SSH agent."""
    try:
        agent_fps = _get_agent_fingerprints()
    except AgentQueryError as exc:
        print(f"WARNING: Cannot check SSH agent keys: {exc}", file=sys.stderr)
        return

    # Collect fingerprint → alias list for hosts with IdentityFile
    missing: dict[str, list[str]] = {}
    for host in hosts:
        if not host.fingerprint:
            continue
        if host.fingerprint not in agent_fps:
            missing.setdefault(host.fingerprint, []).extend(
                a for a in host.aliases if "*" not in a and "?" not in a
            )

    if not missing:
        return

    # Map fingerprint → key_ref name for display, using hostdata entries
    fp_to_key: dict[str, str] = {}
    for host in hosts:
        if host.fingerprint and not fp_to_key.get(host.fingerprint):
            for alias in host.aliases:
                if key_ref := hostdata.get(alias, {}).get("key"):
                    fp_to_key[host.fingerprint] = key_ref
                    break

    print(
        "WARNING: SSH keys exported but not available in the SSH agent:",
        file=sys.stderr,
    )
    for fp, aliases in missing.items():
        key_name = fp_to_key.get(fp, "")
        key_info = f" ({key_name})" if key_name else ""
        alias_list = ", ".join(sorted(set(aliases)))
        print(
            f"  {fp}{key_info}: {alias_list}",
            file=sys.stderr,
        )
    print(
        "  Check that the corresponding keys are enabled in the 1Password SSH agent.",
        file=sys.stderr,
    )


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
    - Normalize dot-refs (op://././field → op://vault/item/field)
    - Check cache (skip resolution if original unchanged)
    - Resolve non-sensitive references via op.resolve()
    - Sensitive fields stay unresolved (resolved at SSH time)
    """

    def _resolve_fv(fv: FieldValue) -> FieldValue:
        """Resolve a single FieldValue using the op-core client."""
        if fv.sensitive:
            return fv
        return fv.with_resolved(op.resolve(fv))

    def _resolve_field(name: str, fv: FieldValue) -> FieldValue:
        try:
            # Auto-complete item-level refs (e.g. password → /password)
            completed = complete_field_refs(fv.original, name)
            if completed != fv.original:
                print(
                    f'ssh-concierge: incomplete reference in field "{name}" '
                    f'on item {meta.display_name} — auto-completed to "{completed}"',
                    file=sys.stderr,
                )
                fv = FieldValue.from_raw(completed, name)

            # Normalize self-refs so the wrapper can resolve without item metadata
            normalized = normalize_original(fv.original, meta.vault_id, meta.item_id)
            if normalized != fv.original:
                fv = FieldValue.from_raw(normalized, name)

            if fv.sensitive:
                return fv  # Don't resolve at generation time

            cached = cached_fields.get(name) if cached_fields and not no_cache else None
            if cached is not None and fv.original == cached.original:
                # Original unchanged — but the target value may have changed.
                # Re-probe via op.resolve: same-item / cross-managed-item refs
                # hit the seeded InMemoryBackend; refs to unmanaged items fall
                # through to the live CLIBackend.
                if cached.field_type == "reference":
                    fresh = op.resolve(fv)
                    if fresh is not None and fresh != cached.resolved:
                        return fv.with_resolved(fresh)
                return cached

            return _resolve_fv(fv)
        except ValueError as exc:
            print(
                f'ssh-concierge: bad reference in field "{name}" '
                f"on item {meta.display_name}: {exc}",
                file=sys.stderr,
            )
            return fv

    return dataclasses.replace(
        host,
        hostname=_resolve_field("hostname", host.hostname) if host.hostname else None,
        port=_resolve_field("port", host.port) if host.port else None,
        user=_resolve_field("user", host.user) if host.user else None,
        password=_resolve_field("password", host.password) if host.password else None,
        otp=_resolve_field("otp", host.otp) if host.otp else None,
        extra_directives={
            k: _resolve_field(k, fv) for k, fv in host.extra_directives.items()
        },
        custom_fields={
            k: _resolve_field(k, fv) for k, fv in host.custom_fields.items()
        },
    )


def _build_hostdata_entry(host: HostConfig) -> dict | None:
    """Build a hostdata entry from a resolved HostConfig.

    Iterates all FieldValues already on the HostConfig and serializes them.
    Returns None if the host has no fields worth storing.
    """
    fields = {name: fv.to_dict() for name, fv in _iter_host_fields(host)}

    entry: dict = {}
    if host.host_filter:
        entry["on"] = host.host_filter
    if host.clipboard:
        entry["clipboard"] = host.clipboard
    if host.key_ref:
        entry["key"] = host.key_ref
    if host.password_prompt:
        entry["password_prompt"] = host.password_prompt
    if host.otp_prompt:
        entry["otp_prompt"] = host.otp_prompt
    if fields:
        entry["fields"] = fields

    return entry or None


def _iter_host_fields(host: HostConfig):
    """Yield (name, FieldValue) for all resolvable fields on a HostConfig."""
    for name, fv in [
        ("password", host.password),
        ("otp", host.otp),
        ("hostname", host.hostname),
        ("port", host.port),
        ("user", host.user),
    ]:
        if fv is not None:
            yield name, fv
    yield from host.extra_directives.items()
    yield from host.custom_fields.items()


def _load_cached_hostdata(hostdata_file: Path) -> dict[str, dict[str, FieldValue]]:
    """Load cached field data from the existing host data cache.

    Returns {alias: {field_name: FieldValue}}.
    """
    if not hostdata_file.is_file():
        return {}
    try:
        data = json.loads(hostdata_file.read_text())
    except (json.JSONDecodeError, OSError):
        return {}

    return {
        alias: {
            name: FieldValue.from_dict(fdata)
            for name, fdata in entry.get("fields", {}).items()
        }
        for alias, entry in data.items()
        if entry.get("fields")
    }


def _extract_key_pair(item: Item) -> tuple[str, str] | None:
    """Extract (public_key, fingerprint) from top-level item fields, or None."""
    public_key = None
    fingerprint = None
    for f in item.top_level_fields():
        if f.label == "public key":
            public_key = f.value
        elif f.label == "fingerprint":
            fingerprint = f.value
    return (public_key, fingerprint) if public_key and fingerprint else None


def _build_key_registry(items: list[Item]) -> dict[tuple, tuple[str, str]]:
    """Build a registry of SSH key data from fetched items.

    Maps (vault_name.lower(), title.lower()) and (item_id,) → (public_key, fingerprint).
    """
    registry: dict[tuple, tuple[str, str]] = {}
    for item in items:
        key_pair = _extract_key_pair(item)
        if not key_pair:
            continue
        if item.vault_name and item.title:
            registry[(item.vault_name.lower(), item.title.lower())] = key_pair
        if item.id:
            registry[(item.id,)] = key_pair
    return registry


def _resolve_key_ref(
    host: HostConfig,
    key_registry: dict,
    op: OnePassword | None = None,
    meta: ItemMeta | None = None,
) -> HostConfig:
    """Resolve a key_ref on a HostConfig against the key registry.

    key_ref must be an op:// reference:
    - op://Vault/Item (fully explicit item ref)
    - op://./Item (same-vault item ref)
    - op://././SSH Config/key (self-ref field, resolved via seeded cache)

    If the host already has a public_key or has no key_ref, returns unchanged.
    """
    if not host.key_ref or host.public_key:
        return host

    aliases = ", ".join(host.aliases)
    key_ref = host.key_ref

    try:
        ref = OpRef.parse(key_ref)
    except ValueError:
        print(
            f'ssh-concierge: invalid key reference "{key_ref}" on host {aliases}',
            file=sys.stderr,
        )
        return host

    # Resolve field-level refs (e.g. op://././SSH Config/key) via seeded cache
    if ref.is_complete and op is not None:
        if ref.is_vault_relative:
            if not meta:
                print(
                    f'ssh-concierge: cannot resolve dot-ref "{key_ref}" '
                    f"without item metadata (host {aliases})",
                    file=sys.stderr,
                )
                return host
            resolved = op.read(ref.as_absolute(meta.vault_id, meta.item_id).for_op())
        else:
            resolved = op.read(ref.for_op())
        if not resolved:
            print(
                f'ssh-concierge: key reference "{key_ref}" '
                f"could not be resolved (host {aliases})",
                file=sys.stderr,
            )
            return host
        # Re-parse the resolved value as an item ref
        try:
            ref = OpRef.parse(resolved)
        except ValueError:
            print(
                f'ssh-concierge: key reference "{key_ref}" '
                f'resolved to invalid ref "{resolved}" (host {aliases})',
                file=sys.stderr,
            )
            return host
        if ref.is_complete:
            print(
                f'ssh-concierge: key reference "{key_ref}" '
                f"resolved to field ref, expected item ref (host {aliases})",
                file=sys.stderr,
            )
            return host

    # At this point ref should be an item-level ref (vault/item, no field)
    if ref.is_vault_relative and not meta:
        print(
            f'ssh-concierge: cannot resolve same-vault ref "{key_ref}" '
            f"without item metadata (host {aliases})",
            file=sys.stderr,
        )
        return host

    vault = meta.vault_name if ref.is_vault_relative and meta else ref.vault
    title = ref.item

    if ref.is_item_relative:
        print(
            'ssh-concierge: key reference cannot use "." '
            f"in item position (host {aliases})",
            file=sys.stderr,
        )
        return host

    key = key_registry.get((vault.lower(), title.lower()))
    if not key:
        print(
            f'ssh-concierge: key "{key_ref}" not found (host {aliases})',
            file=sys.stderr,
        )
        return host

    return dataclasses.replace(host, public_key=key[0], fingerprint=key[1])


def cmd_generate(
    settings: Settings,
    *,
    quiet: bool = False,
    no_cache: bool = False,
) -> None:
    """Query 1Password and regenerate the runtime config."""
    settings.runtime_dir.mkdir(parents=True, exist_ok=True)

    with open(settings.lock_file, "w") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # Another process holds the lock — check if config is now fresh
            hosts_file = settings.hosts_file
            if hosts_file.exists():
                age = time.time() - hosts_file.stat().st_mtime
                if age < settings.ttl:
                    if not quiet:
                        print("Config is fresh (generated by another process)")
                    return  # Another process just regenerated
            # Wait for lock (blocking)
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            # Double-check after acquiring lock
            if hosts_file.exists():
                age = time.time() - hosts_file.stat().st_mtime
                if age < settings.ttl:
                    if not quiet:
                        print("Config is fresh (generated by another process)")
                    return

        if not quiet:
            print("Querying 1Password...")

        live = OnePassword(CLIBackend(timeout=settings.op_timeout))

        # Load cached hostdata for cache comparison
        cached_hostdata = (
            _load_cached_hostdata(settings.hostdata_file) if not no_cache else {}
        )

        # Two list_items calls + dedup: SSH Keys by category, others by tag.
        # op-core ANDs tags+categories, so OR requires two calls.
        summaries_by_id = {}
        for s in live.list_items(categories=["SSH_KEY"]):
            summaries_by_id[s.id] = s
        for s in live.list_items(tags=[SSH_HOST_TAG]):
            summaries_by_id[s.id] = s

        hosts = []
        hostdata: dict[str, dict] = {}

        # First pass: fetch all items, parse into HostConfigs, build key registry
        fetched: list[Item] = []
        parsed: list[tuple[HostConfig, ItemMeta]] = []
        for summary in summaries_by_id.values():
            item = live.get_item(summary)
            fetched.append(item)
            meta = ItemMeta(
                vault_id=item.vault_id,
                item_id=item.id,
                vault_name=item.vault_name,
                item_title=item.title,
            )
            for host in parse_item_to_host_configs(item):
                parsed.append((host, meta))

        key_registry = _build_key_registry(fetched)

        # Build an in-memory client seeded with all fetched items for
        # cache-aware resolution (non-sensitive refs hit local data)
        op = OnePassword(
            InMemoryBackend(
                items=fetched,
                fallback=CLIBackend(timeout=settings.op_timeout),
            )
        )

        # Filter by local hostname
        local_hostname = socket.gethostname()
        parsed = [(h, m) for h, m in parsed if h.matches_host(local_hostname)]

        # Second pass: resolve key refs, expand, resolve fields, generate
        for host, meta in parsed:
            host = _resolve_key_ref(host, key_registry, op, meta)
            for expanded in expand_host_config(host):
                # Use first non-wildcard alias for cache lookup
                cache_alias = next(
                    (a for a in expanded.aliases if "*" not in a and "?" not in a),
                    None,
                )
                cached_fields = (
                    cached_hostdata.get(cache_alias) if cache_alias else None
                )
                resolved_host = resolve_host_fields(
                    expanded,
                    meta,
                    cached_fields,
                    op,
                    no_cache=no_cache,
                )
                hosts.append(resolved_host)
                entry = _build_hostdata_entry(resolved_host)
                if entry:
                    for alias in resolved_host.aliases:
                        if "*" not in alias and "?" not in alias:
                            hostdata[alias] = entry

        generate_runtime_config(
            hosts,
            runtime_dir=settings.runtime_dir,
            keys_dir=settings.keys_dir,
            hosts_file=settings.hosts_file,
            hostdata_file=settings.hostdata_file,
            key_file=settings.key_file,
            hostdata=hostdata or None,
            key_mode=settings.key_mode,
        )
        _write_env_sh(settings)

        password_count = sum(
            1
            for e in hostdata.values()
            if any(f.get("sensitive") for f in e.get("fields", {}).values())
        )
        clipboard_count = sum(1 for e in hostdata.values() if "clipboard" in e)
        if not quiet:
            print(
                f"Generated: {len(hosts)} hosts from {len(fetched)} items"
                f" ({password_count} password, {clipboard_count} clipboard)"
            )
            print(f"Config:    {settings.hosts_file}")
            if hostdata:
                print(f"Hostdata:  {settings.hostdata_file}")
            if settings.ttl == 0:
                print(
                    "Note: Auto-update is disabled (ttl=0). "
                    "Run --generate manually to refresh."
                )

        if password_count > 0:
            _warn_noexec_askpass(settings.askpass_dir)

        _warn_missing_agent_keys(hosts, hostdata)


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
    if settings.ttl == 0:
        status = "manual"
    else:
        status = "STALE" if age_secs >= settings.ttl else "fresh"

    print(f"Config: {conf}")
    print(f"Status: {status} (age: {age_min}m)")
    print(f"Managed hosts: {host_count}")


def _agent_key_status(identity_line: str) -> str:
    """Return an agent status suffix for an IdentityFile line, or empty string.

    Parses the .pub path from the line, reconstructs the fingerprint (filenames
    use '_' instead of '/'), and checks if it's loaded in the SSH agent.
    Returns '  ✓ available in SSH agent', '  ⚠ NOT in SSH agent (...)', or ''.
    """
    parts = identity_line.strip().split(None, 1)
    key_path = parts[1] if len(parts) == 2 else ""
    if not key_path.endswith(".pub"):
        return ""

    fp = Path(key_path).stem.replace("_", "/")
    try:
        agent_fps = _get_agent_fingerprints()
    except AgentQueryError as exc:
        return f"  ⚠ cannot check agent: {exc}"
    if fp in agent_fps:
        return "  ✓ available in SSH agent"
    return "  ⚠ NOT in SSH agent (check 1Password agent vault config)"


def cmd_debug(alias: str, settings: Settings) -> None:
    """Show the generated config block for a given alias."""
    conf = settings.hosts_file
    if not conf.exists():
        print("No config generated yet. Run: ssh-concierge --generate")
        return

    content = conf.read_text()
    lines = content.splitlines()

    # Find the Host block containing this alias
    block_start = None
    for i, line in enumerate(lines):
        if line.startswith("Host "):
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
        if lines[i].startswith("Host "):
            break
        block_lines.append(lines[i])

    # Strip trailing blank lines
    while block_lines and not block_lines[-1].strip():
        block_lines.pop()

    # Print the block
    print("\n".join(block_lines))

    # Look up hostdata
    entry = lookup_hostdata(alias, settings.hostdata_file)
    if entry:
        # Host filter
        on_filter = entry.get("on")
        if on_filter:
            print(f"    # On: {on_filter}")

        # Key reference
        key = entry.get("key")
        identity_line = next(
            (line for line in block_lines if "IdentityFile" in line), None
        )
        if key:
            if not identity_line:
                print(f"    # Key: {key}  ⚠ NOT RESOLVED (no IdentityFile generated)")
            else:
                agent_status = _agent_key_status(identity_line)
                print(f"    # Key: {key}{agent_status}")

        # All fields with resolution status
        fields = entry.get("fields", {})
        if fields:
            print("    # Fields:")
            for name, fdata in fields.items():
                original = fdata.get("original", "?")
                resolved = fdata.get("resolved")
                sensitive = fdata.get("sensitive", False)
                if sensitive:
                    print(
                        f"    #   {name}: {original}  (sensitive, resolved at SSH time)"
                    )
                elif resolved is not None and resolved != original:
                    print(f"    #   {name}: {original} → {resolved}")
                elif resolved is not None:
                    print(f"    #   {name}: {original}")
                else:
                    print(f"    #   {name}: {original}  ⚠ UNRESOLVED")

        # Prompt overrides
        pw_prompt = entry.get("password_prompt")
        if pw_prompt:
            print(f"    # Password prompt: {pw_prompt}")
        otp_prompt = entry.get("otp_prompt")
        if otp_prompt:
            print(f"    # OTP prompt: {otp_prompt}")

        # Clipboard
        clipboard = entry.get("clipboard")
        if clipboard:
            print(f"    # Clipboard: {clipboard!r}")

    # Config age
    age_secs = time.time() - conf.stat().st_mtime
    age_min = int(age_secs // 60)
    if settings.ttl == 0:
        status = "manual"
    else:
        status = "STALE" if age_secs >= settings.ttl else "fresh"
    print(f"\nConfig age: {age_min}m ({status})")


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
            print(f"unknown directive: {directive}", file=sys.stderr)
            print(f"available: {', '.join(Settings.DIRECTIVES)}", file=sys.stderr)
            sys.exit(1)
    else:
        for name in Settings.DIRECTIVES:
            print(f"{name}={settings.get(name)}")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="ssh-concierge",
        description="Dynamic SSH configuration provider backed by 1Password",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--generate",
        action="store_true",
        help="Regenerate runtime config from 1Password",
    )
    group.add_argument("--flush", action="store_true", help="Remove runtime config")
    group.add_argument("--list", action="store_true", help="List managed hosts")
    group.add_argument("--status", action="store_true", help="Show config status")
    group.add_argument(
        "--debug", metavar="ALIAS", help="Show generated config for a host alias"
    )
    group.add_argument("--deploy-key", metavar="ALIAS", help="Deploy SSH key to a host")
    group.add_argument(
        "--config",
        nargs="?",
        const="",
        metavar="DIRECTIVE",
        help="Show config value (or all if no directive given)",
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Deploy to all sibling hosts (only with --deploy-key)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Force re-resolution of all field references",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress informational output"
    )

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
        cmd_deploy_key(args.deploy_key, args.all, settings)
