"""Tests for ssh_concierge.models."""

from tests.conftest import fv

from ssh_concierge.models import HostConfig


class TestHostConfig:
    def test_effective_hostname_explicit(self):
        host = HostConfig(aliases=['prod'], hostname=fv('203.0.113.42', 'hostname'))
        assert host.effective_hostname == '203.0.113.42'

    def test_effective_hostname_defaults_to_first_alias(self):
        host = HostConfig(aliases=['prod', 'prod-web-01'])
        assert host.effective_hostname == 'prod'

    def test_effective_hostname_sensitive_falls_back(self):
        host = HostConfig(aliases=['prod'], hostname=fv('ops://V/I/h', 'hostname'))
        # Sensitive hostname → for_config() returns None → falls back to alias
        assert host.effective_hostname == 'prod'

    def test_host_pattern_single_alias(self):
        host = HostConfig(aliases=['prod'])
        assert host.host_pattern == 'prod'

    def test_host_pattern_multiple_aliases(self):
        host = HostConfig(aliases=['prod', 'prod-web-01', 'production.example.com'])
        assert host.host_pattern == 'prod prod-web-01 production.example.com'

    def test_config_port(self):
        host = HostConfig(aliases=['test'], port=fv('2222', 'port'))
        assert host.config_port == '2222'

    def test_config_port_none(self):
        host = HostConfig(aliases=['test'])
        assert host.config_port is None

    def test_config_user(self):
        host = HostConfig(aliases=['test'], user=fv('deploy', 'user'))
        assert host.config_user == 'deploy'

    def test_config_user_none(self):
        host = HostConfig(aliases=['test'])
        assert host.config_user is None

    def test_config_extra(self):
        host = HostConfig(
            aliases=['test'],
            extra_directives={'ProxyJump': fv('bastion', 'ProxyJump')},
        )
        assert host.config_extra == {'ProxyJump': 'bastion'}

    def test_config_extra_excludes_sensitive(self):
        host = HostConfig(
            aliases=['test'],
            extra_directives={
                'ProxyJump': fv('bastion', 'ProxyJump'),
                'Secret': fv('ops://V/I/s', 'secret'),
            },
        )
        # 'secret' is in SENSITIVE_FIELD_NAMES → for_config() returns None → excluded
        assert host.config_extra == {'ProxyJump': 'bastion'}

    def test_extra_directives_default_empty(self):
        host = HostConfig(aliases=['test'])
        assert host.extra_directives == {}

    def test_frozen(self):
        host = HostConfig(aliases=['test'])
        try:
            host.hostname = fv('changed', 'hostname')  # type: ignore[misc]
            assert False, 'Should raise FrozenInstanceError'
        except AttributeError:
            pass
