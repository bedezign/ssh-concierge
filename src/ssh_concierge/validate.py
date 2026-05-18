"""Pre-flight validation of HostConfigs before runtime config generation.

All checks emit warnings only — never block generation. Use ``validate_configs``
to run all checks against a list of resolved HostConfigs.
"""

from __future__ import annotations

import concurrent.futures
import re
import socket
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum

from op_core import FieldValue, Item, OnePassword, OpRef

from ssh_concierge.models import HostConfig
from ssh_concierge.password import ItemMeta

_CHAIN_SEPARATOR = "||"


class IssueLevel(Enum):
    """Severity of a validation Issue."""

    WARN = "warn"
    ERROR = "error"


@dataclass(frozen=True)
class Issue:
    """A single validation finding."""

    level: IssueLevel
    alias: str
    message: str


def validate_configs(
    host_meta_pairs: list[tuple[HostConfig, ItemMeta, set[str]]],
    item_index: dict[tuple, Item],
    *,
    op: OnePassword | None = None,
    validate_refs: bool = False,
    dns_timeout: float = 2.0,
) -> list[Issue]:
    """Run all pre-flight validators against a set of resolved HostConfigs.

    Returns a list of Issues. Order is not guaranteed but is consistent
    within a single run.

    Args:
        host_meta_pairs: Tuples of (host, meta, field_names) where field_names
            is the set of SSH Config field names on the source item (used by
            the self-reference completeness check).
        item_index: Lookup table for cross-item references. Keyed by both
            ``(vault_id, item_id)`` and ``(vault_name.lower(), title.lower())``.
        op: OnePassword client. Required only when ``validate_refs`` is True.
        validate_refs: Enable deep ref existence checks via the op CLI.
        dns_timeout: Per-host DNS timeout in seconds.
    """
    issues: list[Issue] = []
    issues.extend(_check_duplicate_aliases(host_meta_pairs))
    for host, _, item_fields in host_meta_pairs:
        issues.extend(_check_port_sanity(host))
        issues.extend(_check_clipboard_template(host))
        issues.extend(_check_key_ref(host, item_index))
        issues.extend(_check_reference_syntax(host))
        issues.extend(_check_self_ref_completeness(host, item_fields))
    issues.extend(_check_dns_resolution(host_meta_pairs, dns_timeout=dns_timeout))
    if validate_refs and op is not None:
        issues.extend(_check_deep_references(host_meta_pairs, item_index, op))
    return issues


def _is_wildcard(alias: str) -> bool:
    """Return True if alias contains SSH glob wildcards."""
    return "*" in alias or "?" in alias


def _primary_alias(host: HostConfig) -> str:
    """Return a non-wildcard alias for issue reporting, else the first alias."""
    for alias in host.aliases:
        if not _is_wildcard(alias):
            return alias
    return host.aliases[0] if host.aliases else ""


def _is_unresolved_or_template(value: str) -> bool:
    """Detect values that are not yet ground to a concrete literal."""
    return "op://" in value or "ops://" in value or "{{" in value


def _check_port_sanity(host: HostConfig) -> list[Issue]:
    """Verify host.port (when present) parses to an int in 1..65535."""
    fv_port = host.port
    if fv_port is None:
        return []
    # Prefer resolved literal, fall back to original
    candidate = fv_port.resolved if fv_port.resolved is not None else fv_port.original
    if not candidate:
        return []
    if _is_unresolved_or_template(candidate):
        return []
    try:
        port_int = int(candidate)
    except ValueError:
        return [
            Issue(
                level=IssueLevel.WARN,
                alias=_primary_alias(host),
                message=f'port "{candidate}" is not a valid integer',
            )
        ]
    if port_int < 1 or port_int > 65535:
        return [
            Issue(
                level=IssueLevel.WARN,
                alias=_primary_alias(host),
                message=f"port {port_int} is out of range (must be 1..65535)",
            )
        ]
    return []


def _iter_host_field_values(host: HostConfig) -> Iterator[tuple[str, FieldValue]]:
    """Yield (name, FieldValue) for all resolvable fields on a HostConfig."""
    for name, fv_obj in [
        ("hostname", host.hostname),
        ("port", host.port),
        ("user", host.user),
        ("password", host.password),
        ("otp", host.otp),
    ]:
        if fv_obj is not None:
            yield name, fv_obj
    yield from host.extra_directives.items()
    yield from host.custom_fields.items()


def _collect_cross_item_refs(
    host: HostConfig,
) -> list[tuple[str, str, str]]:
    """Return list of (vault, item, storage_uri) for each cross-item ref on the host.

    A "cross-item" ref means a parseable, complete ``op://``-style reference
    that is NOT vault-relative or item-relative (those are handled by other
    code paths). Sensitive-marker refs are included; the deep check only
    reads the item's title, never its sensitive payload.
    """
    refs: list[tuple[str, str, str]] = []
    for _, field_value in _iter_host_field_values(host):
        original = field_value.original
        if "://" not in original:
            continue
        for segment in original.split(_CHAIN_SEPARATOR):
            stripped = segment.strip()
            if "://" not in stripped:
                continue
            try:
                ref = OpRef.parse(stripped)
            except ValueError:
                continue
            if ref.is_vault_relative or ref.is_item_relative:
                continue
            if not ref.is_complete:
                # item-level ref handled by key-ref check
                continue
            refs.append((ref.vault, ref.item, stripped))
    return refs


def _check_deep_references(
    host_meta_pairs: list[tuple[HostConfig, ItemMeta, set[str]]],
    item_index: dict[tuple, Item],
    op: OnePassword,
) -> list[Issue]:
    """Verify cross-item references resolve to a real item via the op CLI.

    Reads only the item's ``title`` field — never anything sensitive. Caches
    the (vault, item) → existence outcome to avoid duplicate CLI calls.
    """
    cache: dict[tuple[str, str], bool] = {}
    issues: list[Issue] = []
    first_error_logged = False
    for host, _meta, _fields in host_meta_pairs:
        del _meta, _fields  # signature-conforming; only ``host`` is used here
        for vault, item, original in _collect_cross_item_refs(host):
            if (vault.lower(), item.lower()) in item_index:
                continue
            cache_key = (vault, item)
            if cache_key not in cache:
                title_uri = f"op://{vault}/{item}/title"
                try:
                    result = op.read(title_uri)
                except Exception as exc:
                    if not first_error_logged:
                        print(
                            f"validate-refs: op.read failed for {title_uri}: "
                            f"{type(exc).__name__}: {exc}; "
                            f"subsequent failures will be silent",
                            file=sys.stderr,
                        )
                        first_error_logged = True
                    result = None
                cache[cache_key] = result is not None and result != ""
            if cache[cache_key]:
                continue
            issues.append(
                Issue(
                    level=IssueLevel.WARN,
                    alias=_primary_alias(host),
                    message=(
                        f"op:// reference to missing item: "
                        f'"op://{vault}/{item}" (from "{original}")'
                    ),
                )
            )
    return issues


def _is_ip_literal(host: str) -> bool:
    """Return True if ``host`` parses as either an IPv4 or IPv6 literal."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            continue
    return False


def _proxyjump_first_hop(value: str) -> str | None:
    """Extract the first hop from a ProxyJump directive value.

    Strips ``user@`` prefix and ``:port`` suffix from the first comma-
    separated entry. Returns None if the value is empty.
    """
    first = value.split(",", 1)[0].strip()
    if not first:
        return None
    if "@" in first:
        first = first.split("@", 1)[1]
    if first.startswith("["):
        # bracketed IPv6 literal, e.g. [::1]:2222
        end = first.find("]")
        if end != -1:
            return first[1:end]
    if first.count(":") == 1:
        first = first.split(":", 1)[0]
    return first


def _dns_target(host: HostConfig) -> str | None:
    """Resolve which hostname (if any) to send to getaddrinfo.

    Returns None when the host should be skipped (wildcard alias, unresolved
    ref, IP literal, missing target, etc.).
    """
    # Skip wildcard hosts
    if any(_is_wildcard(a) for a in host.aliases):
        return None

    # ProxyJump first hop wins over hostname when set
    jump_fv = host.extra_directives.get("ProxyJump")
    if jump_fv is not None:
        candidate = jump_fv.resolved or jump_fv.original
        if candidate and not _is_unresolved_or_template(candidate):
            return _proxyjump_first_hop(candidate)
        return None

    # If hostname is set but unresolved (still a reference/template), skip.
    if host.hostname is not None:
        if host.hostname.resolved is None:
            if _is_unresolved_or_template(host.hostname.original):
                return None

    candidate = host.effective_hostname
    if not candidate or _is_unresolved_or_template(candidate):
        return None
    if _is_ip_literal(candidate):
        return None
    return candidate


def _resolve_single(target: str, timeout: float) -> tuple[str, Exception | None]:
    """Resolve ``target`` once, returning ``(target, exception_or_None)``.

    Note: ``socket.setdefaulttimeout`` is process-global — there is no
    per-call timeout argument on ``getaddrinfo``. The window is narrowed to
    the duration of the single resolution call, but other threads that also
    call ``getaddrinfo`` concurrently will observe the changed default.
    """
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo(target, None, family=socket.AF_UNSPEC)
        return target, None
    except (TimeoutError, socket.gaierror, OSError) as exc:
        return target, exc
    finally:
        socket.setdefaulttimeout(previous)


def _check_dns_resolution(
    host_meta_pairs: list[tuple[HostConfig, ItemMeta, set[str]]],
    *,
    dns_timeout: float,
) -> list[Issue]:
    """Resolve effective hostnames in parallel; warn on any failure."""
    targets: list[tuple[HostConfig, str]] = []
    for host, _meta, _fields in host_meta_pairs:
        del _meta, _fields  # signature-conforming; only ``host`` is used here
        target = _dns_target(host)
        if target:
            targets.append((host, target))

    if not targets:
        return []

    issues: list[Issue] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {
            pool.submit(_resolve_single, target, dns_timeout): (host, target)
            for host, target in targets
        }
        for future in concurrent.futures.as_completed(futures):
            host, target = futures[future]
            _, exc = future.result()
            if exc is None:
                continue
            issues.append(
                Issue(
                    level=IssueLevel.WARN,
                    alias=_primary_alias(host),
                    message=f'hostname does not resolve: "{target}" ({exc})',
                )
            )
    return issues


def _check_self_ref_completeness(
    host: HostConfig, item_fields: set[str]
) -> list[Issue]:
    """Verify ``op://././field`` self-references name fields on the same item.

    ``item_fields`` is the case-preserved set of field labels on the source
    item's ``SSH Config`` section. Lookup is case-insensitive.
    """
    available = {name.lower() for name in item_fields}
    issues: list[Issue] = []
    for fld_name, field_value in _iter_host_field_values(host):
        original = field_value.original
        if "://" not in original:
            continue
        for segment in original.split(_CHAIN_SEPARATOR):
            stripped = segment.strip()
            if "://" not in stripped:
                continue
            try:
                ref = OpRef.parse(stripped)
            except ValueError:
                continue  # caught by reference-syntax check
            if not (ref.is_complete and ref.is_vault_relative and ref.is_item_relative):
                continue
            target = ref.field_path
            if target is None:
                continue
            # Only check the simple-field-name case (no nested paths)
            target_lower = target.lower()
            if "/" in target_lower:
                continue
            if target_lower not in available:
                issues.append(
                    Issue(
                        level=IssueLevel.WARN,
                        alias=_primary_alias(host),
                        message=(
                            f'self-reference target "{{{target}}}" on field '
                            f'"{fld_name}" does not match any field on the item'
                        ),
                    )
                )
    return issues


def _check_reference_syntax(host: HostConfig) -> list[Issue]:
    """Validate that op://-bearing segments parse as OpRef.

    Walks every FieldValue. For segments separated by ``||`` that contain
    ``://``, attempt to parse and emit a warning on parse failure.
    """
    issues: list[Issue] = []
    for name, field_value in _iter_host_field_values(host):
        original = field_value.original
        if "://" not in original:
            continue
        for segment in original.split(_CHAIN_SEPARATOR):
            stripped = segment.strip()
            if "://" not in stripped:
                continue
            try:
                OpRef.parse(stripped)
            except ValueError as exc:
                issues.append(
                    Issue(
                        level=IssueLevel.WARN,
                        alias=_primary_alias(host),
                        message=(
                            f'reference syntax error in field "{name}": '
                            f'"{stripped}" ({exc})'
                        ),
                    )
                )
    return issues


def _check_key_ref(host: HostConfig, item_index: dict[tuple, Item]) -> list[Issue]:
    """Warn when a cross-item key_ref points at an item not in the index.

    Skips:
    - hosts with no key_ref
    - hosts that already have a public_key (resolved via key registry)
    - field-level refs (handled by ``_resolve_key_ref``)
    - refs that fail to parse (handled by ``_resolve_key_ref``)
    """
    if not host.key_ref or host.public_key:
        return []
    try:
        ref = OpRef.parse(host.key_ref)
    except ValueError:
        return []
    if ref.is_complete:
        # Field-level ref — handled by the existing resolver
        return []
    # Self-vault refs need ItemMeta context; existing resolver path handles them.
    if ref.is_vault_relative:
        return []

    if (ref.vault.lower(), ref.item.lower()) in item_index:
        return []
    return [
        Issue(
            level=IssueLevel.WARN,
            alias=_primary_alias(host),
            message=f'key reference unreachable: "{host.key_ref}" (no such item)',
        )
    ]


_CLIPBOARD_BUILTIN_FIELDS: frozenset[str] = frozenset(
    {"password", "otp", "hostname", "port", "user"}
)
_CLIPBOARD_PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def _check_clipboard_template(host: HostConfig) -> list[Issue]:
    """Verify every {placeholder} in host.clipboard names a known field."""
    if not host.clipboard:
        return []
    known = set(_CLIPBOARD_BUILTIN_FIELDS)
    known.update(k.lower() for k in host.extra_directives)
    known.update(k.lower() for k in host.custom_fields)

    issues: list[Issue] = []
    for match in _CLIPBOARD_PLACEHOLDER.finditer(host.clipboard):
        name = match.group(1)
        if name.lower() not in known:
            issues.append(
                Issue(
                    level=IssueLevel.WARN,
                    alias=_primary_alias(host),
                    message=(
                        f"clipboard references unknown field "
                        f'"{{{name}}}" (no such field on host)'
                    ),
                )
            )
    return issues


def _check_duplicate_aliases(
    host_meta_pairs: list[tuple[HostConfig, ItemMeta, set[str]]],
) -> list[Issue]:
    """Detect aliases appearing on more than one host."""
    by_alias: dict[str, list[tuple[str, str | None]]] = {}
    for host, meta, _ in host_meta_pairs:
        for alias in host.aliases:
            if _is_wildcard(alias):
                continue
            by_alias.setdefault(alias, []).append(
                (meta.display_name, host.section_label)
            )

    issues: list[Issue] = []
    for alias, entries in by_alias.items():
        if len(entries) <= 1:
            continue
        names = ", ".join(
            f"{display} / {label}" if label else display for display, label in entries
        )
        issues.append(
            Issue(
                level=IssueLevel.WARN,
                alias=alias,
                message=f'duplicate alias "{alias}" on items: {names}',
            )
        )
    return issues
