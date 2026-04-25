"""Deploy SSH public keys to remote hosts via ssh-copy-id."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from op_core import (
    CLIBackend,
    FieldValue,
    InMemoryBackend,
    Item,
    ItemSummary,
    OnePassword,
    normalize_original,
)

from ssh_concierge.expand import expand_host_config
from ssh_concierge.models import HostConfig
from ssh_concierge.password import ItemMeta, create_askpass
from ssh_concierge.settings import Settings
from ssh_concierge.ssh_items import SSH_HOST_TAG, parse_item_to_host_configs


def fetch_all_hosts(
    live: OnePassword,
) -> tuple[list[tuple[HostConfig, ItemMeta]], list[Item]]:
    """Query 1Password and return expanded HostConfigs + the raw item list.

    The two-call + dedup listing matches cli.py: op-core ANDs tags+categories,
    so OR across (SSH_KEY category) and (SSH Host tag) requires two list_items
    calls.
    """
    summaries_by_id: dict[str, ItemSummary] = {}
    for s in live.list_items(categories=["SSH_KEY"]):
        summaries_by_id[s.id] = s
    for s in live.list_items(tags=[SSH_HOST_TAG]):
        summaries_by_id[s.id] = s

    fetched: list[Item] = []
    results: list[tuple[HostConfig, ItemMeta]] = []
    for summary in summaries_by_id.values():
        item = live.get_item(summary)
        fetched.append(item)
        meta = ItemMeta(
            vault_id=item.vault_id,
            item_id=item.id,
            vault_name=item.vault_name or "",
            item_title=item.title or "",
        )
        for host in parse_item_to_host_configs(item):
            for expanded in expand_host_config(host):
                results.append((expanded, meta))
    return results, fetched


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
            and not any("*" in a or "?" in a for a in candidate.aliases)
        ):
            siblings.append((candidate, meta))
    return siblings


def _build_ssh_copy_id_args(host: HostConfig, key_path: Path) -> list[str]:
    """Build the ssh-copy-id command arguments for a host."""
    args = ["ssh-copy-id", "-i", str(key_path)]
    if host.port:
        args.extend(["-p", host.port.original])
    target = host.aliases[0]
    if host.user:
        target = f"{host.user.original}@{target}"
    args.append(target)
    return args


def deploy_key_to_host(
    host: HostConfig,
    key_path: Path,
    password: str | None = None,
    askpass_file: Path | None = None,
) -> bool:
    """Deploy a public key to a host using ssh-copy-id.

    Returns True on success, False on failure.
    If password is provided, uses SSH_ASKPASS to automate authentication.
    Otherwise inherits stdin for interactive password prompts.
    """
    args = _build_ssh_copy_id_args(host, key_path)
    print(f"Deploying key to {host.aliases[0]}...")
    try:
        if password:
            assert askpass_file is not None, (
                "askpass_file required when password is set"
            )
            env_vars = create_askpass(password, askpass_file=askpass_file)
            env = {**os.environ, **env_vars}
            result = subprocess.run(
                args,
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
        print("Error: ssh-copy-id not found. Install openssh-client.", file=sys.stderr)
        return False
    return result.returncode == 0


def _ensure_key_file(host: HostConfig, settings: Settings) -> Path | None:
    """Get the public key file path, generating runtime config if needed."""
    if not host.fingerprint or not host.public_key:
        print(f"Error: no SSH key associated with {host.aliases[0]}", file=sys.stderr)
        return None

    key_path = settings.key_file(host.fingerprint)
    if not key_path.exists():
        # Generate runtime config to create key files
        from ssh_concierge.cli import cmd_generate

        cmd_generate(settings)
    if not key_path.exists():
        print(f"Error: key file not found at {key_path}", file=sys.stderr)
        return None
    return key_path


def _resolve_password(
    host: HostConfig,
    meta: ItemMeta,
    op: OnePassword,
) -> str | None:
    """Resolve the password FieldValue on a HostConfig via op-core.

    Normalizes self-refs against the host's item metadata before delegating
    to ``op.resolve``. Returns ``None`` if the host has no password or if
    resolution fails.
    """
    if not host.password:
        return None
    normalized_ref = normalize_original(
        host.password.original, meta.vault_id, meta.item_id
    )
    return op.resolve(FieldValue.from_raw(normalized_ref, "password"))


def cmd_deploy_key(alias: str, all_siblings: bool, settings: Settings) -> None:
    """Deploy SSH key to a host (and optionally its siblings)."""
    live = OnePassword(CLIBackend(timeout=settings.op_timeout))
    hosts, fetched = fetch_all_hosts(live)

    match = resolve_host(alias, hosts)
    if match is None:
        print(f"Error: alias {alias!r} not found in 1Password", file=sys.stderr)
        sys.exit(1)

    host, item_meta = match

    key_path = _ensure_key_file(host, settings)
    if key_path is None:
        sys.exit(1)

    # In-memory resolver seeded with fetched items; sensitive refs still
    # fall through to the live CLIBackend.
    op = OnePassword(
        InMemoryBackend(
            items=fetched,
            fallback=CLIBackend(timeout=settings.op_timeout),
        )
    )
    resolved_pw = _resolve_password(host, item_meta, op)

    targets: list[HostConfig] = [host]
    if all_siblings:
        sibling_hosts = [s for s, _ in find_siblings(host, hosts)]
        if sibling_hosts:
            print(
                f"Including siblings: {', '.join(s.aliases[0] for s in sibling_hosts)}"
            )
            targets.extend(sibling_hosts)

    failed: list[str] = []
    for target in targets:
        if not deploy_key_to_host(
            target, key_path, password=resolved_pw, askpass_file=settings.askpass_file
        ):
            failed.append(target.aliases[0])

    if failed:
        print(f"\nFailed: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)
