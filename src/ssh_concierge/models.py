"""Data models for ssh-concierge."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ssh_concierge.field import FieldValue


@dataclass(frozen=True)
class HostConfig:
    """SSH host configuration extracted from a 1Password item."""

    # Metadata (plain values)
    aliases: list[str]
    public_key: str | None = None
    fingerprint: str | None = None
    section_label: str | None = None
    key_ref: str | None = None

    # Resolvable fields (FieldValue or None)
    hostname: FieldValue | None = None
    port: FieldValue | None = None
    user: FieldValue | None = None
    password: FieldValue | None = None

    # Template string, not a FieldValue (uses {field_name} placeholders)
    clipboard: str | None = None

    # SSH directives and custom data fields
    extra_directives: dict[str, FieldValue] = field(default_factory=dict)
    custom_fields: dict[str, FieldValue] = field(default_factory=dict)

    @property
    def effective_hostname(self) -> str:
        """Hostname to use in config — resolved hostname or first alias."""
        if self.hostname:
            return self.hostname.for_config() or self.aliases[0]
        return self.aliases[0]

    @property
    def config_port(self) -> str | None:
        """Port value for hosts.conf (None if absent or sensitive)."""
        return self.port.for_config() if self.port else None

    @property
    def config_user(self) -> str | None:
        """User value for hosts.conf (None if absent or sensitive)."""
        return self.user.for_config() if self.user else None

    @property
    def config_extra(self) -> dict[str, str]:
        """Extra directives for hosts.conf (excludes sensitive fields)."""
        result: dict[str, str] = {}
        for k, fv in self.extra_directives.items():
            val = fv.for_config()
            if val is not None:
                result[k] = val
        return result

    @property
    def host_pattern(self) -> str:
        """Space-separated aliases for the Host line."""
        return ' '.join(self.aliases)
