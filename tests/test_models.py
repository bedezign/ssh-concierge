"""Tests for ssh_concierge.models."""

from ssh_concierge.models import HostConfig


class TestHostConfig:
    def test_effective_hostname_explicit(self):
        host = HostConfig(aliases=["prod"], hostname="203.0.113.42")
        assert host.effective_hostname == "203.0.113.42"

    def test_effective_hostname_defaults_to_first_alias(self):
        host = HostConfig(aliases=["prod", "prod-web-01"])
        assert host.effective_hostname == "prod"

    def test_host_pattern_single_alias(self):
        host = HostConfig(aliases=["prod"])
        assert host.host_pattern == "prod"

    def test_host_pattern_multiple_aliases(self):
        host = HostConfig(aliases=["prod", "prod-web-01", "production.example.com"])
        assert host.host_pattern == "prod prod-web-01 production.example.com"

    def test_extra_directives_default_empty(self):
        host = HostConfig(aliases=["test"])
        assert host.extra_directives == {}

    def test_frozen(self):
        host = HostConfig(aliases=["test"])
        try:
            host.hostname = "changed"  # type: ignore[misc]
            assert False, "Should raise FrozenInstanceError"
        except AttributeError:
            pass
