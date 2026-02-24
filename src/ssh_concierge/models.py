"""Data models for ssh-concierge."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HostConfig:
    """SSH host configuration extracted from a 1Password item."""

    aliases: list[str]
    hostname: str | None = None
    port: str | None = None
    user: str | None = None
    public_key: str | None = None
    fingerprint: str | None = None
    extra_directives: dict[str, str] = field(default_factory=dict)
    section_label: str | None = None
    password: str | None = None
    clipboard: str | None = None

    @property
    def effective_hostname(self) -> str:
        """Hostname to use in config — explicit hostname or first alias."""
        return self.hostname or self.aliases[0]

    @property
    def host_pattern(self) -> str:
        """Space-separated aliases for the Host line."""
        return " ".join(self.aliases)
