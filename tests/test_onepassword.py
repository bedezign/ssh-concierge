"""Tests for ssh_concierge.onepassword."""

import json
from unittest.mock import patch

import pytest

from ssh_concierge.models import HostConfig
from ssh_concierge.onepassword import (
    _is_managed,
    list_managed_item_ids,
    parse_item_to_host_configs,
    OpError,
)

# Realistic op item list output (mixed categories)
SAMPLE_LIST_OUTPUT = json.dumps([
    {
        "id": "abc123",
        "title": "prod.example.com",
        "tags": ["Servers"],
        "category": "SSH_KEY",
        "additional_information": "SHA256:abc123fingerprint",
    },
    {
        "id": "def456",
        "title": "bastion.example.com",
        "category": "SSH_KEY",
        "additional_information": "SHA256:def456fingerprint",
    },
    {
        "id": "ghi789",
        "title": "password-host.example.com",
        "tags": ["SSH Host"],
        "category": "SERVER",
    },
    {
        "id": "unrelated1",
        "title": "My Gmail",
        "category": "LOGIN",
    },
])

# Single SSH Config section
SAMPLE_ITEM_SINGLE_SECTION = {
    "id": "abc123",
    "title": "prod.example.com",
    "tags": ["Servers"],
    "category": "SSH_KEY",
    "fields": [
        {
            "id": "public_key",
            "type": "STRING",
            "label": "public key",
            "value": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample prod-key",
        },
        {
            "id": "fingerprint",
            "type": "STRING",
            "label": "fingerprint",
            "value": "SHA256:abc123fingerprint",
        },
        {
            "id": "private_key",
            "type": "SSHKEY",
            "label": "private key",
            "value": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
        },
        {
            "id": "notesPlain",
            "type": "STRING",
            "purpose": "NOTES",
            "label": "notesPlain",
        },
        {
            "id": "field1",
            "type": "STRING",
            "label": "aliases",
            "value": "prod, prod-web-01, production.example.com",
            "section": {"id": "sshconfig", "label": "SSH Config"},
        },
        {
            "id": "field2",
            "type": "STRING",
            "label": "hostname",
            "value": "203.0.113.42",
            "section": {"id": "sshconfig", "label": "SSH Config"},
        },
        {
            "id": "field3",
            "type": "STRING",
            "label": "port",
            "value": "2222",
            "section": {"id": "sshconfig", "label": "SSH Config"},
        },
        {
            "id": "field4",
            "type": "STRING",
            "label": "user",
            "value": "deploy",
            "section": {"id": "sshconfig", "label": "SSH Config"},
        },
        {
            "id": "field5",
            "type": "STRING",
            "label": "ProxyJump",
            "value": "bastion",
            "section": {"id": "sshconfig", "label": "SSH Config"},
        },
    ],
}

SAMPLE_ITEM_MINIMAL = {
    "id": "def456",
    "title": "bastion.example.com",
    "category": "SSH_KEY",
    "fields": [
        {
            "id": "public_key",
            "type": "STRING",
            "label": "public key",
            "value": "ssh-rsa AAAAbastion bastion-key",
        },
        {
            "id": "fingerprint",
            "type": "STRING",
            "label": "fingerprint",
            "value": "SHA256:def456fingerprint",
        },
        {
            "id": "private_key",
            "type": "SSHKEY",
            "label": "private key",
            "value": "...",
        },
        {
            "id": "field1",
            "type": "STRING",
            "label": "aliases",
            "value": "bastion",
            "section": {"id": "sshconfig", "label": "SSH Config"},
        },
    ],
}

SAMPLE_ITEM_NO_SSH_SECTION = {
    "id": "nossh",
    "title": "plain-key",
    "category": "SSH_KEY",
    "fields": [
        {
            "id": "public_key",
            "type": "STRING",
            "label": "public key",
            "value": "ssh-ed25519 AAAAplain plain-key",
        },
        {
            "id": "fingerprint",
            "type": "STRING",
            "label": "fingerprint",
            "value": "SHA256:plainfingerprint",
        },
    ],
}

# Multiple SSH Config sections on one item
SAMPLE_ITEM_MULTI_SECTION = {
    "id": "clusterkey",
    "title": "admin.cluster1.example.com",
    "category": "SSH_KEY",
    "fields": [
        {
            "id": "public_key",
            "type": "STRING",
            "label": "public key",
            "value": "ssh-ed25519 AAAAclusterkey",
        },
        {
            "id": "fingerprint",
            "type": "STRING",
            "label": "fingerprint",
            "value": "SHA256:clusterfingerprint",
        },
        # Section 1: wildcard
        {
            "id": "f1",
            "label": "aliases",
            "value": "*.cluster1.example.com",
            "section": {"id": "sec1", "label": "SSH Config: cluster-wildcard"},
        },
        {
            "id": "f2",
            "label": "user",
            "value": "admin",
            "section": {"id": "sec1", "label": "SSH Config: cluster-wildcard"},
        },
        # Section 2: short names
        {
            "id": "f3",
            "label": "aliases",
            "value": "master{1,2}, worker{1..3}, utility1",
            "section": {"id": "sec2", "label": "SSH Config: cluster-short"},
        },
        {
            "id": "f4",
            "label": "hostname",
            "value": "%h.cluster1.example.com",
            "section": {"id": "sec2", "label": "SSH Config: cluster-short"},
        },
        {
            "id": "f5",
            "label": "user",
            "value": "admin",
            "section": {"id": "sec2", "label": "SSH Config: cluster-short"},
        },
    ],
}


class TestIsManaged:
    def test_ssh_key_category(self):
        assert _is_managed({"category": "SSH_KEY"}) is True

    def test_ssh_key_with_tags(self):
        assert _is_managed({"category": "SSH_KEY", "tags": ["Servers"]}) is True

    def test_ssh_host_tag(self):
        assert _is_managed({"category": "SERVER", "tags": ["SSH Host"]}) is True

    def test_ssh_host_tag_among_others(self):
        assert _is_managed({"category": "LOGIN", "tags": ["SSH Host", "Work"]}) is True

    def test_unrelated_item(self):
        assert _is_managed({"category": "LOGIN"}) is False

    def test_unrelated_with_tags(self):
        assert _is_managed({"category": "LOGIN", "tags": ["Work"]}) is False

    def test_no_category_with_tag(self):
        assert _is_managed({"tags": ["SSH Host"]}) is True


class TestListManagedItemIds:
    @patch("ssh_concierge.onepassword._run_op")
    def test_returns_managed_ids(self, mock_run):
        mock_run.return_value = SAMPLE_LIST_OUTPUT
        ids = list_managed_item_ids()
        assert ids == ["abc123", "def456", "ghi789"]

    @patch("ssh_concierge.onepassword._run_op")
    def test_excludes_unrelated(self, mock_run):
        mock_run.return_value = SAMPLE_LIST_OUTPUT
        ids = list_managed_item_ids()
        assert "unrelated1" not in ids

    @patch("ssh_concierge.onepassword._run_op")
    def test_empty_list(self, mock_run):
        mock_run.return_value = "[]"
        ids = list_managed_item_ids()
        assert ids == []

    @patch("ssh_concierge.onepassword._run_op")
    def test_op_failure_raises(self, mock_run):
        mock_run.side_effect = OpError("op not signed in")
        with pytest.raises(OpError):
            list_managed_item_ids()


class TestParseItemToHostConfigs:
    def test_single_section(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_SINGLE_SECTION)
        assert len(hosts) == 1
        host = hosts[0]
        assert host.aliases == ["prod", "prod-web-01", "production.example.com"]
        assert host.hostname == "203.0.113.42"
        assert host.port == "2222"
        assert host.user == "deploy"
        assert host.public_key == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample prod-key"
        assert host.fingerprint == "SHA256:abc123fingerprint"
        assert host.extra_directives == {"ProxyJump": "bastion"}
        assert host.section_label == "SSH Config"

    def test_minimal_item(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_MINIMAL)
        assert len(hosts) == 1
        host = hosts[0]
        assert host.aliases == ["bastion"]
        assert host.hostname is None
        assert host.port is None
        assert host.user is None
        assert host.public_key == "ssh-rsa AAAAbastion bastion-key"
        assert host.fingerprint == "SHA256:def456fingerprint"
        assert host.extra_directives == {}

    def test_no_ssh_config_section_returns_empty(self):
        result = parse_item_to_host_configs(SAMPLE_ITEM_NO_SSH_SECTION)
        assert result == []

    def test_aliases_whitespace_trimmed(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_SINGLE_SECTION)
        assert hosts[0].aliases == ["prod", "prod-web-01", "production.example.com"]

    def test_alias_singular_fallback(self):
        """'alias' (singular) field is accepted as fallback for 'aliases'."""
        item = {
            "id": "x",
            "title": "Plex",
            "category": "LOGIN",
            "tags": ["SSH Host"],
            "fields": [
                {
                    "id": "f1",
                    "label": "alias",
                    "value": "plex",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "hostname",
                    "value": "mediabox.local",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert len(hosts) == 1
        assert hosts[0].aliases == ["plex"]
        assert hosts[0].hostname == "mediabox.local"

    def test_aliases_plural_takes_precedence_over_singular(self):
        """When both 'aliases' and 'alias' exist, 'aliases' wins."""
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "server1, server2",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "alias",
                    "value": "server-old",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert len(hosts) == 1
        assert hosts[0].aliases == ["server1", "server2"]

    def test_host_fallback_for_hostname(self):
        """'host' field is accepted as fallback for 'hostname'."""
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "myserver",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "host",
                    "value": "192.168.1.100",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert len(hosts) == 1
        assert hosts[0].hostname == "192.168.1.100"
        assert hosts[0].extra_directives == {}

    def test_hostname_takes_precedence_over_host(self):
        """When both 'hostname' and 'host' exist, 'hostname' wins."""
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "myserver",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "hostname",
                    "value": "10.0.0.1",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f3",
                    "label": "host",
                    "value": "10.0.0.99",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert hosts[0].hostname == "10.0.0.1"

    def test_username_fallback_for_user(self):
        """'username' field is accepted as fallback for 'user'."""
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "myserver",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "username",
                    "value": "deploy",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert len(hosts) == 1
        assert hosts[0].user == "deploy"
        assert hosts[0].extra_directives == {}

    def test_user_takes_precedence_over_username(self):
        """When both 'user' and 'username' exist, 'user' wins."""
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "myserver",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "user",
                    "value": "admin",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f3",
                    "label": "username",
                    "value": "old-user",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert hosts[0].user == "admin"

    def test_known_fields_case_insensitive(self):
        """Field names like 'User', 'PORT' are recognized as known fields."""
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {"id": "pk", "label": "public key", "value": "ssh-ed25519 AAAA"},
                {"id": "fp", "label": "fingerprint", "value": "SHA256:x"},
                {
                    "id": "f1",
                    "label": "Aliases",
                    "value": "myserver",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "User",
                    "value": "deploy",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f3",
                    "label": "PORT",
                    "value": "2222",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f4",
                    "label": "HostName",
                    "value": "10.0.0.1",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert len(hosts) == 1
        assert hosts[0].aliases == ["myserver"]
        assert hosts[0].user == "deploy"
        assert hosts[0].port == "2222"
        assert hosts[0].hostname == "10.0.0.1"
        assert hosts[0].extra_directives == {}

    def test_empty_aliases_skipped(self):
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        result = parse_item_to_host_configs(item)
        assert result == []

    def test_multi_section(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_MULTI_SECTION)
        assert len(hosts) == 2

        # Section 1: wildcard
        assert hosts[0].aliases == ["*.cluster1.example.com"]
        assert hosts[0].hostname is None
        assert hosts[0].user == "admin"
        assert hosts[0].fingerprint == "SHA256:clusterfingerprint"
        assert hosts[0].section_label == "SSH Config: cluster-wildcard"

        # Section 2: short names with brace expansion
        assert hosts[1].aliases == [
            "master1", "master2",
            "worker1", "worker2", "worker3",
            "utility1",
        ]
        assert hosts[1].hostname == "%h.cluster1.example.com"
        assert hosts[1].user == "admin"
        assert hosts[1].section_label == "SSH Config: cluster-short"

    def test_multi_section_shares_key(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_MULTI_SECTION)
        # Both sections share the item's public key and fingerprint
        for host in hosts:
            assert host.public_key == "ssh-ed25519 AAAAclusterkey"
            assert host.fingerprint == "SHA256:clusterfingerprint"

    def test_duplicate_aliases_deduplicated(self):
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {"id": "pk", "label": "public key", "value": "ssh-ed25519 AAAA"},
                {"id": "fp", "label": "fingerprint", "value": "SHA256:x"},
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "bastion1, node01, node01",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert hosts[0].aliases == ["bastion1", "node01"]

    def test_password_extracted(self):
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {"id": "pk", "label": "public key", "value": "ssh-ed25519 AAAA"},
                {"id": "fp", "label": "fingerprint", "value": "SHA256:x"},
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "myhost",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "password",
                    "value": "op://./password",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert hosts[0].password == "op://./password"

    def test_password_not_in_extra_directives(self):
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {"id": "pk", "label": "public key", "value": "ssh-ed25519 AAAA"},
                {"id": "fp", "label": "fingerprint", "value": "SHA256:x"},
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "myhost",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "password",
                    "value": "hunter2",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert "password" not in hosts[0].extra_directives

    def test_no_password_field(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_MINIMAL)
        assert hosts[0].password is None

    def test_clipboard_extracted(self):
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {"id": "pk", "label": "public key", "value": "ssh-ed25519 AAAA"},
                {"id": "fp", "label": "fingerprint", "value": "SHA256:x"},
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "myhost",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "clipboard",
                    "value": "sudo -i\\n{password}\\n",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert hosts[0].clipboard == "sudo -i\\n{password}\\n"

    def test_clipboard_not_in_extra_directives(self):
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {"id": "pk", "label": "public key", "value": "ssh-ed25519 AAAA"},
                {"id": "fp", "label": "fingerprint", "value": "SHA256:x"},
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "myhost",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "clipboard",
                    "value": "some template",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert "clipboard" not in hosts[0].extra_directives

    def test_no_clipboard_field(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_MINIMAL)
        assert hosts[0].clipboard is None

    def test_brace_expansion_in_aliases(self):
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {"id": "pk", "label": "public key", "value": "ssh-ed25519 AAAA"},
                {"id": "fp", "label": "fingerprint", "value": "SHA256:x"},
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "node{1..3}",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert hosts[0].aliases == ["node1", "node2", "node3"]


class TestDirectiveValidation:
    """Tests for SSH directive validation in extra_directives."""

    def _make_item(self, extra_fields: list[dict]) -> dict:
        """Build an item with SSH Config section containing given extra fields."""
        fields = [
            {"id": "pk", "label": "public key", "value": "ssh-ed25519 AAAA"},
            {"id": "fp", "label": "fingerprint", "value": "SHA256:x"},
            {
                "id": "f1",
                "label": "aliases",
                "value": "myhost",
                "section": {"id": "s", "label": "SSH Config"},
            },
        ]
        for i, ef in enumerate(extra_fields):
            fields.append({
                "id": f"extra{i}",
                "label": ef["label"],
                "value": ef["value"],
                "section": {"id": "s", "label": "SSH Config"},
            })
        return {
            "id": "test-item",
            "title": "Test Host",
            "category": "SSH_KEY",
            "fields": fields,
        }

    def test_valid_directive_passes(self):
        item = self._make_item([{"label": "ProxyJump", "value": "bastion"}])
        hosts = parse_item_to_host_configs(item)
        assert len(hosts) == 1
        assert hosts[0].extra_directives == {"ProxyJump": "bastion"}

    def test_multiple_valid_directives(self):
        item = self._make_item([
            {"label": "ProxyJump", "value": "bastion"},
            {"label": "ForwardAgent", "value": "yes"},
        ])
        hosts = parse_item_to_host_configs(item)
        assert len(hosts) == 1
        assert hosts[0].extra_directives == {
            "ProxyJump": "bastion",
            "ForwardAgent": "yes",
        }

    def test_invalid_directive_skips_host(self, capsys):
        item = self._make_item([{"label": "foobar", "value": "baz"}])
        hosts = parse_item_to_host_configs(item)
        assert hosts == []
        err = capsys.readouterr().err
        assert 'unknown SSH directive "foobar"' in err
        assert "Test Host" in err

    def test_case_insensitive_valid(self):
        """Lowercase 'proxyjump' is accepted and normalized to canonical 'ProxyJump'."""
        item = self._make_item([{"label": "proxyjump", "value": "bastion"}])
        hosts = parse_item_to_host_configs(item)
        assert len(hosts) == 1
        assert hosts[0].extra_directives == {"ProxyJump": "bastion"}

    def test_case_insensitive_mixed_case(self):
        """'PROXYJUMP' is accepted and normalized to canonical 'ProxyJump'."""
        item = self._make_item([{"label": "PROXYJUMP", "value": "bastion"}])
        hosts = parse_item_to_host_configs(item)
        assert len(hosts) == 1
        assert hosts[0].extra_directives == {"ProxyJump": "bastion"}

    def test_mixed_valid_and_invalid_skips_host(self, capsys):
        """One invalid directive among valid ones causes the entire host to be skipped."""
        item = self._make_item([
            {"label": "ProxyJump", "value": "bastion"},
            {"label": "NotARealDirective", "value": "oops"},
        ])
        hosts = parse_item_to_host_configs(item)
        assert hosts == []
        err = capsys.readouterr().err
        assert 'unknown SSH directive "NotARealDirective"' in err

    def test_warning_includes_section_label(self, capsys):
        """Warning message includes the section label for multi-section items."""
        item = {
            "id": "x",
            "title": "Multi Host",
            "category": "SSH_KEY",
            "fields": [
                {"id": "pk", "label": "public key", "value": "ssh-ed25519 AAAA"},
                {"id": "fp", "label": "fingerprint", "value": "SHA256:x"},
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "good-host",
                    "section": {"id": "s1", "label": "SSH Config: prod"},
                },
                {
                    "id": "f2",
                    "label": "ProxyJump",
                    "value": "bastion",
                    "section": {"id": "s1", "label": "SSH Config: prod"},
                },
                {
                    "id": "f3",
                    "label": "aliases",
                    "value": "bad-host",
                    "section": {"id": "s2", "label": "SSH Config: staging"},
                },
                {
                    "id": "f4",
                    "label": "typofield",
                    "value": "oops",
                    "section": {"id": "s2", "label": "SSH Config: staging"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        # Good section passes, bad section skipped
        assert len(hosts) == 1
        assert hosts[0].aliases == ["good-host"]
        err = capsys.readouterr().err
        assert "SSH Config: staging" in err
        assert 'typofield' in err

    def test_existing_proxyjump_still_works(self):
        """Regression: the existing SAMPLE_ITEM_SINGLE_SECTION with ProxyJump still parses."""
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_SINGLE_SECTION)
        assert len(hosts) == 1
        assert hosts[0].extra_directives == {"ProxyJump": "bastion"}


class TestKeyFieldExtraction:
    """Tests for the 'key' field extraction into key_ref."""

    def test_key_extracted(self):
        item = {
            "id": "x",
            "title": "x",
            "category": "SERVER",
            "tags": ["SSH Host"],
            "fields": [
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "myhost",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "key",
                    "value": "op://Work/MySSHKey",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert len(hosts) == 1
        assert hosts[0].key_ref == "op://Work/MySSHKey"

    def test_key_not_in_extra_directives(self):
        item = {
            "id": "x",
            "title": "x",
            "category": "SERVER",
            "tags": ["SSH Host"],
            "fields": [
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "myhost",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "key",
                    "value": "op://Work/MySSHKey",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert "key" not in hosts[0].extra_directives

    def test_no_key_field(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_MINIMAL)
        assert hosts[0].key_ref is None

    def test_key_with_ssh_key_item(self):
        """Key field on an SSH Key item (which already has public_key)."""
        item = {
            "id": "x",
            "title": "x",
            "category": "SSH_KEY",
            "fields": [
                {"id": "pk", "label": "public key", "value": "ssh-ed25519 AAAA"},
                {"id": "fp", "label": "fingerprint", "value": "SHA256:x"},
                {
                    "id": "f1",
                    "label": "aliases",
                    "value": "myhost",
                    "section": {"id": "s", "label": "SSH Config"},
                },
                {
                    "id": "f2",
                    "label": "key",
                    "value": "op://Work/OtherKey",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(item)
        assert hosts[0].key_ref == "op://Work/OtherKey"
        # public_key still comes from item-level fields
        assert hosts[0].public_key == "ssh-ed25519 AAAA"
