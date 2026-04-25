# pyright: reportOptionalMemberAccess=false, reportOptionalSubscript=false
"""Tests for ssh_concierge.ssh_items.parse_item_to_host_configs."""

from op_core import Item, ItemField, ItemSection

from ssh_concierge.ssh_items import parse_item_to_host_configs


def _item_from_dict(data: dict) -> Item:
    """Build an op_core Item from a compact dict fixture.

    Accepts the old ssh-concierge fixture shape (field list with inline
    ``section: {id, label}`` entries) and maps it to the normalized
    :class:`Item` shape. Any field without a ``section`` key becomes a
    top-level field.
    """
    sections_by_id: dict[str, ItemSection] = {}
    item_fields: list[ItemField] = []
    for fd in data.get("fields", []):
        section = fd.get("section")
        section_id: str | None = None
        if section:
            section_id = str(section["id"])
            if section_id not in sections_by_id:
                sections_by_id[section_id] = ItemSection(
                    id=section_id, label=str(section.get("label", ""))
                )
        item_fields.append(
            ItemField(
                id=fd.get("id", ""),
                label=fd.get("label", ""),
                value=fd.get("value"),
                type=fd.get("type", "STRING"),
                section_id=section_id,
            )
        )
    return Item(
        id=data.get("id", ""),
        title=data.get("title", ""),
        vault_id=data.get("vault_id", "vault-default"),
        vault_name=data.get("vault_name", "Vault"),
        category=data.get("category", ""),
        tags=tuple(data.get("tags", [])),
        sections=tuple(sections_by_id.values()),
        fields=tuple(item_fields),
    )


# Single SSH Config section
SAMPLE_ITEM_SINGLE_SECTION = _item_from_dict(
    {
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
                "value": (
                    "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
                ),
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
)

SAMPLE_ITEM_MINIMAL = _item_from_dict(
    {
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
)

SAMPLE_ITEM_NO_SSH_SECTION = _item_from_dict(
    {
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
)

# Multiple SSH Config sections on one item
SAMPLE_ITEM_MULTI_SECTION = _item_from_dict(
    {
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
)


class TestParseItemToHostConfigs:
    def test_single_section(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_SINGLE_SECTION)
        assert len(hosts) == 1
        host = hosts[0]
        assert host.aliases == ["prod", "prod-web-01", "production.example.com"]
        assert host.hostname.original == "203.0.113.42"
        assert host.port.original == "2222"
        assert host.user.original == "deploy"
        assert (
            host.public_key == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample prod-key"
        )
        assert host.fingerprint == "SHA256:abc123fingerprint"
        assert "ProxyJump" in host.extra_directives
        assert host.extra_directives["ProxyJump"].original == "bastion"
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
            "title": "Mediabox",
            "category": "LOGIN",
            "tags": ["SSH Host"],
            "fields": [
                {
                    "id": "f1",
                    "label": "alias",
                    "value": "mediabox",
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert len(hosts) == 1
        assert hosts[0].aliases == ["mediabox"]
        assert hosts[0].hostname.original == "mediabox.local"

    def test_aliases_plural_takes_precedence_over_singular(self):
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert len(hosts) == 1
        assert hosts[0].aliases == ["server1", "server2"]

    def test_host_fallback_for_hostname(self):
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert len(hosts) == 1
        assert hosts[0].hostname.original == "192.168.1.100"
        assert hosts[0].extra_directives == {}

    def test_hostname_takes_precedence_over_host(self):
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert hosts[0].hostname.original == "10.0.0.1"

    def test_username_fallback_for_user(self):
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert len(hosts) == 1
        assert hosts[0].user.original == "deploy"
        assert hosts[0].extra_directives == {}

    def test_user_takes_precedence_over_username(self):
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert hosts[0].user.original == "admin"

    def test_known_fields_case_insensitive(self):
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert len(hosts) == 1
        assert hosts[0].aliases == ["myserver"]
        assert hosts[0].user.original == "deploy"
        assert hosts[0].port.original == "2222"
        assert hosts[0].hostname.original == "10.0.0.1"
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
                }
            ],
        }
        result = parse_item_to_host_configs(_item_from_dict(item))
        assert result == []

    def test_multi_section(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_MULTI_SECTION)
        assert len(hosts) == 2

        # Section 1: wildcard
        assert hosts[0].aliases == ["*.cluster1.example.com"]
        assert hosts[0].hostname is None
        assert hosts[0].user.original == "admin"
        assert hosts[0].fingerprint == "SHA256:clusterfingerprint"
        assert hosts[0].section_label == "SSH Config: cluster-wildcard"

        # Section 2: short names with brace expansion
        assert hosts[1].aliases == [
            "master1",
            "master2",
            "worker1",
            "worker2",
            "worker3",
            "utility1",
        ]
        assert hosts[1].hostname.original == "%h.cluster1.example.com"
        assert hosts[1].user.original == "admin"
        assert hosts[1].section_label == "SSH Config: cluster-short"

    def test_multi_section_shares_key(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_MULTI_SECTION)
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
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
                    "value": "op://././password",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert hosts[0].password.original == "op://././password"
        assert hosts[0].password.sensitive is True

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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert hosts[0].aliases == ["node1", "node2", "node3"]


class TestDirectiveValidation:
    """Tests for SSH directive validation in extra_directives."""

    def _make_item(self, extra_fields: list[dict]) -> dict:
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
            fields.append(
                {
                    "id": f"extra{i}",
                    "label": ef["label"],
                    "value": ef["value"],
                    "section": {"id": "s", "label": "SSH Config"},
                }
            )
        return {
            "id": "test-item",
            "title": "Test Host",
            "category": "SSH_KEY",
            "fields": fields,
        }

    def test_valid_directive_passes(self):
        item = self._make_item([{"label": "ProxyJump", "value": "bastion"}])
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert len(hosts) == 1
        assert hosts[0].extra_directives["ProxyJump"].original == "bastion"

    def test_multiple_valid_directives(self):
        item = self._make_item(
            [
                {"label": "ProxyJump", "value": "bastion"},
                {"label": "ForwardAgent", "value": "yes"},
            ]
        )
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert len(hosts) == 1
        assert hosts[0].extra_directives["ProxyJump"].original == "bastion"
        assert hosts[0].extra_directives["ForwardAgent"].original == "yes"

    def test_unknown_field_stored_as_custom(self):
        item = self._make_item([{"label": "foobar", "value": "baz"}])
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert len(hosts) == 1
        assert hosts[0].extra_directives == {}
        assert hosts[0].custom_fields["foobar"].original == "baz"

    def test_case_insensitive_valid(self):
        item = self._make_item([{"label": "proxyjump", "value": "bastion"}])
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert hosts[0].extra_directives["ProxyJump"].original == "bastion"

    def test_case_insensitive_mixed_case(self):
        item = self._make_item([{"label": "PROXYJUMP", "value": "bastion"}])
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert hosts[0].extra_directives["ProxyJump"].original == "bastion"

    def test_mixed_valid_and_custom_fields(self):
        item = self._make_item(
            [
                {"label": "ProxyJump", "value": "bastion"},
                {"label": "NotARealDirective", "value": "oops"},
            ]
        )
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert hosts[0].extra_directives["ProxyJump"].original == "bastion"
        assert hosts[0].custom_fields["NotARealDirective"].original == "oops"

    def test_custom_fields_in_multi_section(self):
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
                    "value": "other-host",
                    "section": {"id": "s2", "label": "SSH Config: staging"},
                },
                {
                    "id": "f4",
                    "label": "sudo_password",
                    "value": "ops://./sudo_password",
                    "section": {"id": "s2", "label": "SSH Config: staging"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert len(hosts) == 2
        assert hosts[0].aliases == ["good-host"]
        assert hosts[0].extra_directives["ProxyJump"].original == "bastion"
        assert hosts[1].aliases == ["other-host"]
        assert (
            hosts[1].custom_fields["sudo_password"].original == "ops://./sudo_password"
        )

    def test_existing_proxyjump_still_works(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_SINGLE_SECTION)
        assert len(hosts) == 1
        assert hosts[0].extra_directives["ProxyJump"].original == "bastion"


class TestOnFieldExtraction:
    def test_on_field_extracted(self):
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
                    "label": "on",
                    "value": "alpha, beta",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert len(hosts) == 1
        assert hosts[0].host_filter == "alpha, beta"

    def test_no_on_field(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_MINIMAL)
        assert hosts[0].host_filter is None

    def test_on_not_in_extra_directives(self):
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
                    "label": "on",
                    "value": "alpha",
                    "section": {"id": "s", "label": "SSH Config"},
                },
            ],
        }
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert "on" not in hosts[0].extra_directives
        assert "on" not in hosts[0].custom_fields


class TestKeyFieldExtraction:
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert "key" not in hosts[0].extra_directives

    def test_no_key_field(self):
        hosts = parse_item_to_host_configs(SAMPLE_ITEM_MINIMAL)
        assert hosts[0].key_ref is None

    def test_key_with_ssh_key_item(self):
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
        hosts = parse_item_to_host_configs(_item_from_dict(item))
        assert hosts[0].key_ref == "op://Work/OtherKey"
        assert hosts[0].public_key == "ssh-ed25519 AAAA"
