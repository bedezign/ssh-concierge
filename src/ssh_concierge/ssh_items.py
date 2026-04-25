"""Parse 1Password items into SSH host configurations."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Mapping

from op_core import FieldValue, Item, ItemField, complete_field_refs, expand_braces

from ssh_concierge.models import HostConfig

__all__ = (
    "SSH_CONFIG_SECTION_PREFIX",
    "SSH_HOST_TAG",
    "complete_field_refs",
    "parse_item_to_host_configs",
)

logger = logging.getLogger(__name__)

# Fields from "SSH Config" handled explicitly (including alternate names)
_KNOWN_FIELDS = {
    "aliases",
    "alias",
    "hostname",
    "host",
    "port",
    "user",
    "username",
    "password",
    "otp",
    "clipboard",
    "key",
    "on",
    "password_prompt",
    "otp_prompt",
}

# Valid SSH client config keywords (from man ssh_config, OpenSSH 8.x-9.x).
# Maps lowercase → canonical casing. User input is normalized to the canonical form.
# Excludes keywords we generate ourselves: Host, Match, Include, HostName, Port,
# User, IdentityFile, IdentitiesOnly.
_VALID_SSH_DIRECTIVES: dict[str, str] = {
    k.lower(): k
    for k in (
        "AddKeysToAgent",
        "AddressFamily",
        "BatchMode",
        "BindAddress",
        "BindInterface",
        "CanonicalDomains",
        "CanonicalizeFallbackLocal",
        "CanonicalizeHostname",
        "CanonicalizeMaxDots",
        "CanonicalizePermittedCNAMEs",
        "CASignatureAlgorithms",
        "CertificateFile",
        "ChannelTimeout",
        "CheckHostIP",
        "Ciphers",
        "ClearAllForwardings",
        "Compression",
        "ConnectionAttempts",
        "ConnectTimeout",
        "ControlMaster",
        "ControlPath",
        "ControlPersist",
        "DynamicForward",
        "EnableEscapeCommandline",
        "EnableSSHKeysign",
        "EscapeChar",
        "ExitOnForwardFailure",
        "FingerprintHash",
        "ForkAfterAuthentication",
        "ForwardAgent",
        "ForwardX11",
        "ForwardX11Timeout",
        "ForwardX11Trusted",
        "GatewayPorts",
        "GlobalKnownHostsFile",
        "GSSAPIAuthentication",
        "GSSAPIDelegateCredentials",
        "GSSAPIKeyExchange",
        "GSSAPIRenewalForcesRekey",
        "GSSAPIServerIdentity",
        "GSSAPITrustDns",
        "HashKnownHosts",
        "HostbasedAcceptedAlgorithms",
        "HostbasedAuthentication",
        "HostKeyAlgorithms",
        "HostKeyAlias",
        "IdentityAgent",
        "IgnoreUnknown",
        "IPQoS",
        "KbdInteractiveAuthentication",
        "KbdInteractiveDevices",
        "KexAlgorithms",
        "KnownHostsCommand",
        "LocalCommand",
        "LocalForward",
        "LogLevel",
        "LogVerbose",
        "MACs",
        "NoHostAuthenticationForLocalhost",
        "NumberOfPasswordPrompts",
        "ObfuscateKeystrokes",
        "PasswordAuthentication",
        "PermitLocalCommand",
        "PermitRemoteOpen",
        "PKCS11Provider",
        "PreferredAuthentications",
        "ProxyCommand",
        "ProxyJump",
        "ProxyUseFdpass",
        "PubkeyAcceptedAlgorithms",
        "PubkeyAuthentication",
        "RekeyLimit",
        "RemoteCommand",
        "RemoteForward",
        "RequestTTY",
        "RequiredRSASize",
        "RevokedHostKeys",
        "SecurityKeyProvider",
        "SendEnv",
        "ServerAliveCountMax",
        "ServerAliveInterval",
        "SessionType",
        "SetEnv",
        "StreamLocalBindMask",
        "StreamLocalBindUnlink",
        "StrictHostKeyChecking",
        "SyslogFacility",
        "TCPKeepAlive",
        "Tunnel",
        "TunnelDevice",
        "UpdateHostKeys",
        "UseKeychain",
        "UserKnownHostsFile",
        "VerifyHostKeyDNS",
        "VisualHostKey",
        "XAuthLocation",
    )
}

SSH_CONFIG_SECTION_PREFIX = "SSH Config"
SSH_HOST_TAG = "SSH Host"


def parse_item_to_host_configs(
    item: Item,
    *,
    known_items: Mapping[str, Item] | None = None,
) -> list[HostConfig]:
    """Parse a 1Password item into HostConfigs.

    Supports multiple sections per item: any section whose label starts with
    "SSH Config" produces a HostConfig. All share the item's public key and
    fingerprint.

    ``known_items`` is a by-title map of all fetched items, used to resolve
    cross-item ``key`` references.

    Returns empty list if no SSH Config sections found.
    """
    # Extract public key + fingerprint from top-level fields
    public_key = None
    fingerprint = None
    for field in item.top_level_fields():
        if field.label == "public key":
            public_key = field.value
        elif field.label == "fingerprint":
            fingerprint = field.value

    # Find all SSH Config* sections and group their fields.
    # Each section maps lowercase field name → (original_label, value)
    # so known-field lookups are case-insensitive while extra directives
    # preserve the user's original casing.
    ssh_sections: dict[str, list[ItemField]] = defaultdict(list)
    for section in item.sections:
        if section.label.startswith(SSH_CONFIG_SECTION_PREFIX):
            for field in item.fields_in(section):
                if field.value:
                    ssh_sections[section.label].append(field)

    # Build a HostConfig per section
    hosts = []
    for section_label, fields in ssh_sections.items():
        # Build the case-insensitive lookup: lowercase label → (original_label, value).
        # All fields here have truthy `value` (filtered above when populating
        # ssh_sections), so the `or ""` is a type-narrowing no-op.
        ssh_fields: dict[str, tuple[str, str]] = {}
        for field in fields:
            ssh_fields[field.label.lower()] = (field.label, field.value or "")

        aliases_val = (
            ssh_fields.get("aliases", (None, ""))[1]
            or ssh_fields.get("alias", (None, ""))[1]
        )
        aliases = _parse_aliases(aliases_val)
        if not aliases:
            continue

        # Separate valid SSH directives from custom data fields
        valid_extra = {}
        custom_fields = {}
        for k, (orig_label, v) in ssh_fields.items():
            if k in _KNOWN_FIELDS:
                continue
            if k in _VALID_SSH_DIRECTIVES:
                valid_extra[k] = v
            else:
                # Preserve original label casing for custom fields
                custom_fields[orig_label] = v

        # Normalize to canonical SSH config casing, wrap in FieldValue
        extra = {
            _VALID_SSH_DIRECTIVES[k]: FieldValue.from_raw(v, _VALID_SSH_DIRECTIVES[k])
            for k, v in valid_extra.items()
        }

        # Wrap custom fields in FieldValue
        custom_fv = {
            label: FieldValue.from_raw(v, label) for label, v in custom_fields.items()
        }

        def _val(key: str) -> str | None:
            entry = ssh_fields.get(key)
            return entry[1] if entry else None

        def _fv(key: str, *fallback_keys: str) -> FieldValue | None:
            """Get a field value as FieldValue, trying key then fallbacks."""
            raw = next(
                (v for k in (key, *fallback_keys) if (v := _val(k)) is not None), None
            )
            return FieldValue.from_raw(raw, key) if raw is not None else None

        hosts.append(
            HostConfig(
                aliases=aliases,
                hostname=_fv("hostname", "host"),
                port=_fv("port"),
                user=_fv("user", "username"),
                public_key=public_key,
                fingerprint=fingerprint,
                extra_directives=extra,
                custom_fields=custom_fv,
                section_label=section_label,
                password=_fv("password"),
                otp=_fv("otp"),
                clipboard=_val("clipboard"),
                key_ref=_val("key"),
                host_filter=_val("on"),
                password_prompt=_val("password_prompt"),
                otp_prompt=_val("otp_prompt"),
            )
        )

    return hosts


def _parse_aliases(raw: str) -> list[str]:
    """Parse comma-separated aliases with brace expansion.

    Splits on commas that are not inside braces, then expands each part.
    """
    aliases = []
    seen: set[str] = set()
    for part in _split_outside_braces(raw):
        part = part.strip()
        if part:
            for alias in expand_braces(part):
                if alias not in seen:
                    seen.add(alias)
                    aliases.append(alias)
    return aliases


def _split_outside_braces(text: str) -> list[str]:
    """Split on commas that are not inside curly braces."""
    parts = []
    current: list[str] = []
    depth = 0
    for char in text:
        if char == "{":
            depth += 1
            current.append(char)
        elif char == "}":
            depth = max(0, depth - 1)
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts
