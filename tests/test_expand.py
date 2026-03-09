"""Tests for expansion utilities: brace expansion + regex directives."""

from tests.conftest import fv

import pytest

from ssh_concierge.expand import expand_braces, expand_host_config
from ssh_concierge.models import HostConfig


class TestExpandBraces:
    def test_no_braces(self):
        assert expand_braces("simple") == ["simple"]

    def test_comma_list(self):
        assert expand_braces("host{1,2,3}") == ["host1", "host2", "host3"]

    def test_range(self):
        assert expand_braces("worker{1..4}") == ["worker1", "worker2", "worker3", "worker4"]

    def test_prefix_and_suffix(self):
        assert expand_braces("prd{1,2}x") == ["prd1x", "prd2x"]

    def test_range_with_prefix(self):
        assert expand_braces("worker{1..3}.example.com") == [
            "worker1.example.com",
            "worker2.example.com",
            "worker3.example.com",
        ]

    def test_single_value_range(self):
        assert expand_braces("host{5..5}") == ["host5"]

    def test_comma_with_multi_char(self):
        assert expand_braces("{master,worker,utility}1") == ["master1", "worker1", "utility1"]

    def test_no_expansion_literal_braces(self):
        # Braces without valid expansion syntax pass through
        assert expand_braces("host{}") == ["host{}"]

    def test_multiple_braces_not_supported(self):
        # Only first brace pair is expanded
        result = expand_braces("{a,b}{1,2}")
        assert len(result) == 2  # expands first only


class TestExpandHostConfig:
    # --- no regex: pass through ---

    def test_no_regex_passthrough(self):
        host = HostConfig(aliases=["prod", "prod-web"], hostname=fv("10.0.0.1", "hostname"))
        result = expand_host_config(host)
        assert result == [host]

    def test_none_hostname_passthrough(self):
        host = HostConfig(aliases=["prod"])
        result = expand_host_config(host)
        assert result == [host]

    def test_percent_h_not_regex(self):
        host = HostConfig(aliases=["master1", "worker1"], hostname=fv("%h.example.com", "hostname"))
        result = expand_host_config(host)
        assert result == [host]

    # --- regex hostname ---

    def test_regex_hostname(self):
        host = HostConfig(
            aliases=["prdmaster1", "prdmaster2", "prdworker1"],
            hostname=fv(r"s/^prd(.+)/\1.cluster1prd.example.com/", "hostname"),
            user=fv("jdoe", "user"),
            public_key="ssh-ed25519 AAAAkey",
            fingerprint="SHA256:abc",
        )
        result = expand_host_config(host)
        assert len(result) == 3

        assert result[0].aliases == ["prdmaster1"]
        assert result[0].hostname.raw == "master1.cluster1prd.example.com"
        assert result[0].user.raw == "jdoe"
        assert result[0].fingerprint == "SHA256:abc"

        assert result[1].aliases == ["prdmaster2"]
        assert result[1].hostname.raw == "master2.cluster1prd.example.com"

        assert result[2].aliases == ["prdworker1"]
        assert result[2].hostname.raw == "worker1.cluster1prd.example.com"

    def test_regex_hostname_append_suffix(self):
        host = HostConfig(
            aliases=["master1", "worker1"],
            hostname=fv(r"s/(.+)/\1.cluster1.example.com/", "hostname"),
        )
        result = expand_host_config(host)
        assert result[0].hostname.raw == "master1.cluster1.example.com"
        assert result[1].hostname.raw == "worker1.cluster1.example.com"

    # --- regex user (PSMP pattern) ---

    def test_regex_user(self):
        host = HostConfig(
            aliases=["paserver1", "paserver2"],
            hostname=fv("pam-gateway.example.com", "hostname"),
            user=fv(r"s/^pa(.+)/jdoe@pajdoe%corp.example.com@\1.example.com/", "user"),
        )
        result = expand_host_config(host)
        assert len(result) == 2

        assert result[0].aliases == ["paserver1"]
        assert result[0].hostname.raw == "pam-gateway.example.com"
        assert result[0].user.raw == "jdoe@pajdoe%corp.example.com@server1.example.com"

        assert result[1].aliases == ["paserver2"]
        assert result[1].user.raw == "jdoe@pajdoe%corp.example.com@server2.example.com"

    def test_regex_user_with_static_hostname(self):
        """Hostname stays fixed when only user has regex."""
        host = HostConfig(
            aliases=["a", "b"],
            hostname=fv("proxy.example.com", "hostname"),
            user=fv(r"s/(.+)/admin@\1.internal/", "user"),
        )
        result = expand_host_config(host)
        assert result[0].hostname.raw == "proxy.example.com"
        assert result[1].hostname.raw == "proxy.example.com"
        assert result[0].user.raw == "admin@a.internal"
        assert result[1].user.raw == "admin@b.internal"

    # --- regex extra directives ---

    def test_regex_extra_directive(self):
        host = HostConfig(
            aliases=["server1", "server2"],
            hostname=fv("10.0.0.1", "hostname"),
            extra_directives={
                "LocalForward": fv(r"s/(.+)/8080 \1.internal:80/", "LocalForward"),
                "ProxyJump": fv("bastion", "ProxyJump"),
            },
        )
        result = expand_host_config(host)
        assert len(result) == 2
        assert result[0].extra_directives["LocalForward"].raw == "8080 server1.internal:80"
        assert result[0].extra_directives["ProxyJump"].raw == "bastion"
        assert result[1].extra_directives["LocalForward"].raw == "8080 server2.internal:80"

    # --- {{alias}} placeholder ---

    def test_alias_in_user(self):
        host = HostConfig(
            aliases=["node01", "node02"],
            hostname=fv("pam-gateway.example.com", "hostname"),
            user=fv("jdoe@pajdoe%corp.example.com@{{alias}}.example.com", "user"),
        )
        result = expand_host_config(host)
        assert len(result) == 2
        assert result[0].aliases == ["node01"]
        assert result[0].hostname.raw == "pam-gateway.example.com"
        assert result[0].user.raw == "jdoe@pajdoe%corp.example.com@node01.example.com"
        assert result[1].user.raw == "jdoe@pajdoe%corp.example.com@node02.example.com"

    def test_alias_in_hostname(self):
        host = HostConfig(
            aliases=["master1", "worker1"],
            hostname=fv("{{alias}}.cluster1.example.com", "hostname"),
        )
        result = expand_host_config(host)
        assert result[0].hostname.raw == "master1.cluster1.example.com"
        assert result[1].hostname.raw == "worker1.cluster1.example.com"

    def test_alias_in_extra_directive(self):
        host = HostConfig(
            aliases=["web1", "web2"],
            hostname=fv("10.0.0.1", "hostname"),
            extra_directives={"LocalForward": fv("8080 {{alias}}.internal:80", "LocalForward")},
        )
        result = expand_host_config(host)
        assert result[0].extra_directives["LocalForward"].raw == "8080 web1.internal:80"
        assert result[1].extra_directives["LocalForward"].raw == "8080 web2.internal:80"

    def test_alias_not_triggered_without_placeholder(self):
        host = HostConfig(aliases=["a", "b"], hostname=fv("10.0.0.1", "hostname"), user=fv("admin", "user"))
        result = expand_host_config(host)
        assert result == [host]

    # --- mixed regex + static ---

    def test_section_label_preserved(self):
        host = HostConfig(
            aliases=["master1", "worker1"],
            hostname=fv(r"s/(.+)/\1.example.com/", "hostname"),
            section_label="SSH Config: cluster",
        )
        result = expand_host_config(host)
        assert len(result) == 2
        assert result[0].section_label == "SSH Config: cluster"
        assert result[1].section_label == "SSH Config: cluster"

    def test_preserves_non_regex_fields(self):
        host = HostConfig(
            aliases=["prdmaster1"],
            hostname=fv(r"s/^prd(.+)/\1.cluster1prd.example.com/", "hostname"),
            port=fv("22", "port"),
            user=fv("admin", "user"),
            extra_directives={"ProxyJump": fv("bastion", "ProxyJump")},
        )
        result = expand_host_config(host)
        assert result[0].port.raw == "22"
        assert result[0].user.raw == "admin"
        assert result[0].extra_directives["ProxyJump"].raw == "bastion"

    def test_password_preserved_through_expansion(self):
        host = HostConfig(
            aliases=["master1", "worker1"],
            hostname=fv(r"s/(.+)/\1.example.com/", "hostname"),
            password=fv("op://./password", "password"),
        )
        result = expand_host_config(host)
        assert len(result) == 2
        assert result[0].password.raw == "op://./password"
        assert result[1].password.raw == "op://./password"

    def test_password_preserved_no_expansion(self):
        host = HostConfig(
            aliases=["myhost"],
            hostname=fv("10.0.0.1", "hostname"),
            password=fv("literal-pw", "password"),
        )
        result = expand_host_config(host)
        assert result == [host]
        assert result[0].password.raw == "literal-pw"

    def test_key_ref_preserved_through_expansion(self):
        host = HostConfig(
            aliases=["master1", "worker1"],
            hostname=fv(r"s/(.+)/\1.example.com/", "hostname"),
            key_ref="op://Work/MyKey",
        )
        result = expand_host_config(host)
        assert len(result) == 2
        assert result[0].key_ref == "op://Work/MyKey"
        assert result[1].key_ref == "op://Work/MyKey"

    def test_key_ref_preserved_no_expansion(self):
        host = HostConfig(
            aliases=["myhost"],
            hostname=fv("10.0.0.1", "hostname"),
            key_ref="op://Work/MyKey",
        )
        result = expand_host_config(host)
        assert result == [host]
        assert result[0].key_ref == "op://Work/MyKey"

    def test_host_filter_preserved_through_expansion(self):
        host = HostConfig(
            aliases=["master1", "worker1"],
            hostname=fv(r"s/(.+)/\1.example.com/", "hostname"),
            host_filter="alpha, beta",
        )
        result = expand_host_config(host)
        assert len(result) == 2
        assert result[0].host_filter == "alpha, beta"
        assert result[1].host_filter == "alpha, beta"

    def test_clipboard_preserved_through_expansion(self):
        host = HostConfig(
            aliases=["master1", "worker1"],
            hostname=fv(r"s/(.+)/\1.example.com/", "hostname"),
            clipboard="sudo -i\\n{password}\\n",
        )
        result = expand_host_config(host)
        assert len(result) == 2
        assert result[0].clipboard == "sudo -i\\n{password}\\n"
        assert result[1].clipboard == "sudo -i\\n{password}\\n"
