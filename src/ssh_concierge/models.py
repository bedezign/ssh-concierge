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
    host_filter: str | None = None

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
        """Port value for SSH config output (None if absent or sensitive)."""
        return self.port.for_config() if self.port else None

    @property
    def config_user(self) -> str | None:
        """User value for SSH config output (None if absent or sensitive)."""
        return self.user.for_config() if self.user else None

    @property
    def config_extra(self) -> dict[str, str]:
        """Extra directives for SSH config output (excludes sensitive fields)."""
        return {k: val for k, fv in self.extra_directives.items() if (val := fv.for_config()) is not None}

    def matches_host(self, hostname: str) -> bool:
        """Check if this config should be generated on the given hostname.

        Returns True if no filter is set, filter is '*', or the hostname
        matches the filter criteria. Supports 'not' prefix for negation.
        Matching is case-insensitive. Filter entry 'alpha' matches both
        'alpha' and 'alpha.example.com'.
        """
        if not self.host_filter or self.host_filter.strip() == '*':
            return True

        raw = self.host_filter.strip()
        negate = raw.lower().startswith('not ')
        if negate:
            raw = raw[4:]

        entries = [e.strip().lower() for e in raw.split(',') if e.strip()]
        hostname_lower = hostname.lower()
        short_hostname = hostname_lower.split('.', 1)[0]

        matched = any(
            e == hostname_lower or e == short_hostname
            for e in entries
        )
        return not matched if negate else matched

    @property
    def host_pattern(self) -> str:
        """Space-separated aliases for the Host line."""
        return ' '.join(self.aliases)
