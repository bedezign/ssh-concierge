# pyright: reportOptionalMemberAccess=false, reportOptionalSubscript=false
"""Tests for ssh_concierge.validate."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest
from op_core import FieldValue, Item

from ssh_concierge.models import HostConfig
from ssh_concierge.password import ItemMeta
from ssh_concierge.validate import (
    IssueLevel,
    _check_port_sanity,
    _proxyjump_first_hop,
    validate_configs,
)
from tests.conftest import fv


def _meta(
    vault_id: str = "v1",
    item_id: str = "i1",
    vault_name: str = "Work",
    item_title: str = "Server",
) -> ItemMeta:
    """Build an ItemMeta for tests."""
    return ItemMeta(
        vault_id=vault_id,
        item_id=item_id,
        vault_name=vault_name,
        item_title=item_title,
    )


def _ok_host(aliases: list[str]) -> HostConfig:
    """A minimal hostable HostConfig with a literal IP."""
    return HostConfig(
        aliases=aliases,
        hostname=fv("127.0.0.1", "hostname"),
    )


class TestDuplicateAliases:
    def test_duplicate_alias_emits_issue(self):
        host1 = _ok_host(["prod"])
        host2 = _ok_host(["prod"])
        pairs = [
            (host1, _meta(item_id="i1", item_title="ItemA"), set()),
            (host2, _meta(item_id="i2", item_title="ItemB"), set()),
        ]
        issues = validate_configs(pairs, item_index={})

        dup_issues = [i for i in issues if "duplicate" in i.message.lower()]
        assert len(dup_issues) == 1
        # Both item display names should be visible
        assert "ItemA" in dup_issues[0].message
        assert "ItemB" in dup_issues[0].message
        assert dup_issues[0].alias == "prod"
        assert dup_issues[0].level == IssueLevel.WARN

    def test_no_duplicates_no_issue(self):
        pairs = [
            (_ok_host(["a"]), _meta(item_id="i1"), set()),
            (_ok_host(["b"]), _meta(item_id="i2"), set()),
        ]
        issues = validate_configs(pairs, item_index={})
        dup_issues = [i for i in issues if "duplicate" in i.message.lower()]
        assert dup_issues == []

    def test_wildcards_excluded_from_duplicate_check(self):
        host1 = _ok_host(["*.example.com"])
        host2 = _ok_host(["*.example.com"])
        pairs = [
            (host1, _meta(item_id="i1"), set()),
            (host2, _meta(item_id="i2"), set()),
        ]
        issues = validate_configs(pairs, item_index={})
        dup_issues = [i for i in issues if "duplicate" in i.message.lower()]
        assert dup_issues == []

    def test_same_item_multiple_sections_sharing_alias(self):
        """Same item with multiple SSH Config sections that share an alias."""
        meta = _meta(item_id="i1", item_title="MultiSection")
        host_a = HostConfig(
            aliases=["sectionalpha"],
            hostname=fv("127.0.0.1", "hostname"),
            section_label="SSH Config A",
        )
        host_b = HostConfig(
            aliases=["sectionalpha"],
            hostname=fv("127.0.0.1", "hostname"),
            section_label="SSH Config B",
        )
        pairs = [(host_a, meta, set()), (host_b, meta, set())]
        issues = validate_configs(pairs, item_index={})
        dup_issues = [i for i in issues if "duplicate" in i.message.lower()]
        # Still a duplicate — two distinct host blocks contending for one alias
        assert len(dup_issues) == 1


def _host_with_port(port_fv: FieldValue | None) -> HostConfig:
    """Build a HostConfig with a single literal hostname and a port FieldValue."""
    return HostConfig(
        aliases=["server"],
        hostname=fv("127.0.0.1", "hostname"),
        port=port_fv,
    )


class TestPortSanity:
    def test_valid_port_22_no_issue(self):
        host = _host_with_port(fv("22", "port"))
        issues = validate_configs([(host, _meta(), set())], item_index={})
        port_issues = [i for i in issues if "port" in i.message.lower()]
        assert port_issues == []

    def test_valid_port_2222_no_issue(self):
        host = _host_with_port(fv("2222", "port"))
        issues = validate_configs([(host, _meta(), set())], item_index={})
        port_issues = [i for i in issues if "port" in i.message.lower()]
        assert port_issues == []

    def test_port_zero_emits_issue(self):
        host = _host_with_port(fv("0", "port"))
        issues = validate_configs([(host, _meta(), set())], item_index={})
        port_issues = [i for i in issues if "port" in i.message.lower()]
        assert len(port_issues) == 1
        assert port_issues[0].alias == "server"

    def test_port_too_large_emits_issue(self):
        host = _host_with_port(fv("65536", "port"))
        issues = validate_configs([(host, _meta(), set())], item_index={})
        port_issues = [i for i in issues if "port" in i.message.lower()]
        assert len(port_issues) == 1

    def test_port_non_numeric_emits_issue(self):
        host = _host_with_port(fv("abc", "port"))
        issues = validate_configs([(host, _meta(), set())], item_index={})
        port_issues = [i for i in issues if "port" in i.message.lower()]
        assert len(port_issues) == 1

    def test_unresolved_op_ref_skipped(self):
        # Reference whose original still has op:// — skip
        unresolved = FieldValue(
            original="op://Vault/Item/port",
            resolved=None,
            sensitive=False,
            field_type="reference",
        )
        host = _host_with_port(unresolved)
        issues = validate_configs([(host, _meta(), set())], item_index={})
        port_issues = [i for i in issues if "port" in i.message.lower()]
        assert port_issues == []

    def test_unexpanded_template_skipped(self):
        tmpl = FieldValue(
            original="{{alias}}",
            resolved=None,
            sensitive=False,
            field_type="template",
        )
        host = _host_with_port(tmpl)
        issues = validate_configs([(host, _meta(), set())], item_index={})
        port_issues = [i for i in issues if "port" in i.message.lower()]
        assert port_issues == []

    def test_none_port_skipped(self):
        host = _host_with_port(None)
        issues = validate_configs([(host, _meta(), set())], item_index={})
        port_issues = [i for i in issues if "port" in i.message.lower()]
        assert port_issues == []

    def test_negative_port_emits_issue(self):
        host = _host_with_port(
            FieldValue(
                original="-1", resolved=None, sensitive=False, field_type="literal"
            )
        )
        issues = _check_port_sanity(host)
        assert len(issues) == 1
        assert issues[0].message.startswith("port -1 is out of range")

    def test_port_1_no_issue(self):
        host = _host_with_port(fv("1", "port"))
        issues = _check_port_sanity(host)
        assert issues == []


class TestProxyJumpFirstHop:
    def test_malformed_ipv6_returned_unchanged(self):
        """Malformed bracketed IPv6 (no closing bracket) is returned as-is.

        When find(']') returns -1 the bracket branch is skipped; count(':') > 1
        so the single-colon strip is also skipped. The input passes through
        unchanged. This pins the observable behavior against a slice-wraparound
        regression.
        """
        result = _proxyjump_first_hop("[::1::")
        assert result == "[::1::"


class TestClipboardTemplate:
    def test_known_password_placeholder_no_issue(self):
        host = HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            password=fv("op://V/I/password", "password"),
            clipboard="sudo -i\n{password}\n",
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        clip_issues = [i for i in issues if "clipboard" in i.message.lower()]
        assert clip_issues == []

    def test_unknown_placeholder_emits_issue(self):
        host = HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            password=fv("op://V/I/password", "password"),
            clipboard="x={passwordx}",
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        clip_issues = [i for i in issues if "clipboard" in i.message.lower()]
        assert len(clip_issues) == 1
        assert "passwordx" in clip_issues[0].message
        assert clip_issues[0].alias == "server"

    def test_no_clipboard_skipped(self):
        host = _ok_host(["server"])
        issues = validate_configs([(host, _meta(), set())], item_index={})
        clip_issues = [i for i in issues if "clipboard" in i.message.lower()]
        assert clip_issues == []

    def test_clipboard_without_placeholders_no_issue(self):
        host = HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            clipboard="just a literal string",
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        clip_issues = [i for i in issues if "clipboard" in i.message.lower()]
        assert clip_issues == []

    def test_extra_directive_placeholder_case_insensitive(self):
        """Placeholder name matches extra_directive case-insensitively."""
        host = HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            extra_directives={"ProxyJump": fv("bastion", "ProxyJump")},
            clipboard="{proxyjump}",
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        clip_issues = [i for i in issues if "clipboard" in i.message.lower()]
        assert clip_issues == []

    def test_custom_field_placeholder(self):
        host = HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            custom_fields={"customer": fv("Acme", "customer")},
            clipboard="hello {customer}",
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        clip_issues = [i for i in issues if "clipboard" in i.message.lower()]
        assert clip_issues == []


def _stub_item(item_id: str, title: str, vault_name: str = "Work") -> Item:
    """Minimal Item used to populate the validator item index."""
    return Item(
        id=item_id,
        title=title,
        vault_id="v1",
        vault_name=vault_name,
        category="SSH_KEY",
        tags=(),
        sections=(),
        fields=(),
    )


def _index_from(items: list[Item]) -> dict[tuple, Item]:
    """Build an item_index dict mirroring the validator's expected shape."""
    index: dict[tuple, Item] = {}
    for item in items:
        index[(item.vault_id, item.id)] = item
        if item.vault_name and item.title:
            index[(item.vault_name.lower(), item.title.lower())] = item
    return index


class TestKeyRef:
    def test_key_ref_resolved_via_vault_title_no_issue(self):
        item = _stub_item("k1", "Target Key")
        host = HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            key_ref="op://Work/Target Key",
            # public_key is None — host hasn't been resolved through key registry
        )
        issues = validate_configs(
            [(host, _meta(), set())], item_index=_index_from([item])
        )
        key_issues = [
            i
            for i in issues
            if "key" in i.message.lower() and "miss" in i.message.lower()
        ]
        assert key_issues == []

    def test_key_ref_missing_item_emits_issue(self):
        host = HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            key_ref="op://Work/Nonexistent",
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        key_issues = [
            i
            for i in issues
            if "key" in i.message.lower() and "unreach" in i.message.lower()
        ]
        assert len(key_issues) == 1
        assert key_issues[0].alias == "server"

    def test_key_ref_with_public_key_already_resolved_skipped(self):
        """When public_key is already populated, no validation issue."""
        host = HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            key_ref="op://Work/Nonexistent",
            public_key="ssh-ed25519 AAAA",
            fingerprint="SHA256:abc",
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        key_issues = [
            i
            for i in issues
            if "unreach" in i.message.lower() and "key" in i.message.lower()
        ]
        assert key_issues == []

    def test_field_level_key_ref_skipped(self):
        """A key_ref pointing at a field (op://././SSH Config/key) is handled
        elsewhere (existing _resolve_key_ref path) — validator does not duplicate."""
        host = HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            key_ref="op://././SSH Config/key",
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        key_issues = [
            i
            for i in issues
            if "unreach" in i.message.lower() and "key" in i.message.lower()
        ]
        assert key_issues == []


def _ref(original: str, _: str, sensitive: bool = False) -> FieldValue:
    """FieldValue carrying a reference-typed value.

    The second positional arg is the field name — kept for callsite
    documentation (matches the field's name) but unused here because
    :class:`FieldValue` has no name slot.
    """
    return FieldValue(
        original=original,
        resolved=None,
        sensitive=sensitive,
        field_type="reference",
    )


class TestReferenceSyntax:
    def test_valid_reference_no_issue(self):
        host = HostConfig(
            aliases=["server"],
            hostname=_ref("op://Work/Server/hostname", "hostname"),
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        ref_issues = [
            i
            for i in issues
            if "reference" in i.message.lower() and "syntax" in i.message.lower()
        ]
        assert ref_issues == []

    def test_literal_value_skipped(self):
        host = _ok_host(["server"])
        issues = validate_configs([(host, _meta(), set())], item_index={})
        ref_issues = [i for i in issues if "syntax" in i.message.lower()]
        assert ref_issues == []

    def test_malformed_reference_emits_issue(self):
        # op:/Vault/... — only one slash after prefix is invalid (parse should fail)
        host = HostConfig(
            aliases=["server"],
            hostname=_ref("op://OnlyVault", "hostname"),
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        ref_issues = [
            i
            for i in issues
            if "reference" in i.message.lower() and "syntax" in i.message.lower()
        ]
        assert len(ref_issues) >= 1
        assert ref_issues[0].alias == "server"

    def test_fallback_chain_bad_segment_emits_issue(self):
        """A chain with at least one malformed reference segment is flagged."""
        host = HostConfig(
            aliases=["server"],
            hostname=_ref("op://OnlyVault||fallback", "hostname"),
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        ref_issues = [
            i
            for i in issues
            if "reference" in i.message.lower() and "syntax" in i.message.lower()
        ]
        assert len(ref_issues) >= 1

    def test_fallback_chain_all_ok_no_issue(self):
        host = HostConfig(
            aliases=["server"],
            hostname=_ref("op://Work/Server/hostname||10.0.0.1", "hostname"),
        )
        issues = validate_configs([(host, _meta(), set())], item_index={})
        ref_issues = [
            i
            for i in issues
            if "reference" in i.message.lower() and "syntax" in i.message.lower()
        ]
        assert ref_issues == []


class TestSelfRefCompleteness:
    def test_self_ref_field_exists_no_issue(self):
        host = HostConfig(
            aliases=["server"],
            hostname=_ref("op://././hostname", "hostname"),
        )
        item_fields = {"aliases", "hostname"}
        issues = validate_configs([(host, _meta(), item_fields)], item_index={})
        sref_issues = [
            i
            for i in issues
            if "self-reference" in i.message.lower() or "self ref" in i.message.lower()
        ]
        assert sref_issues == []

    def test_self_ref_field_missing_emits_issue(self):
        # references "pwd" but item has only "password"
        host = HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            password=_ref("op://././pwd", "password", sensitive=True),
        )
        item_fields = {"aliases", "password"}
        issues = validate_configs([(host, _meta(), item_fields)], item_index={})
        sref_issues = [
            i
            for i in issues
            if "self-reference" in i.message.lower() or "self ref" in i.message.lower()
        ]
        assert len(sref_issues) == 1
        assert "pwd" in sref_issues[0].message

    def test_self_ref_case_insensitive_match(self):
        host = HostConfig(
            aliases=["server"],
            hostname=_ref("op://././HostName", "hostname"),
        )
        item_fields = {"hostname"}
        issues = validate_configs([(host, _meta(), item_fields)], item_index={})
        sref_issues = [
            i
            for i in issues
            if "self-reference" in i.message.lower() or "self ref" in i.message.lower()
        ]
        assert sref_issues == []


class TestDnsResolution:
    def test_resolvable_hostname_no_issue(self):
        host = HostConfig(
            aliases=["server"],
            hostname=fv("resolvable.example.com", "hostname"),
        )
        with patch("ssh_concierge.validate.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(socket.AF_INET, 0, 0, "", ("10.0.0.1", 0))]
            issues = validate_configs([(host, _meta(), set())], item_index={})
        dns_issues = [i for i in issues if "resolve" in i.message.lower()]
        assert dns_issues == []

    def test_unresolvable_hostname_emits_issue(self):
        host = HostConfig(
            aliases=["server"],
            hostname=fv("does-not-exist.example.invalid", "hostname"),
        )
        with patch("ssh_concierge.validate.socket.getaddrinfo") as mock_gai:
            mock_gai.side_effect = socket.gaierror("nodename or servname not provided")
            issues = validate_configs([(host, _meta(), set())], item_index={})
        dns_issues = [i for i in issues if "resolve" in i.message.lower()]
        assert len(dns_issues) == 1
        assert dns_issues[0].alias == "server"
        assert "does-not-exist.example.invalid" in dns_issues[0].message

    def test_ipv4_literal_skipped(self):
        host = _ok_host(["server"])  # hostname = 127.0.0.1
        with patch("ssh_concierge.validate.socket.getaddrinfo") as mock_gai:
            mock_gai.side_effect = socket.gaierror("should not be called")
            issues = validate_configs([(host, _meta(), set())], item_index={})
        dns_issues = [i for i in issues if "resolve" in i.message.lower()]
        assert dns_issues == []
        mock_gai.assert_not_called()

    def test_ipv6_literal_skipped(self):
        host = HostConfig(
            aliases=["server"],
            hostname=fv("::1", "hostname"),
        )
        with patch("ssh_concierge.validate.socket.getaddrinfo") as mock_gai:
            mock_gai.side_effect = socket.gaierror("should not be called")
            issues = validate_configs([(host, _meta(), set())], item_index={})
        dns_issues = [i for i in issues if "resolve" in i.message.lower()]
        assert dns_issues == []
        mock_gai.assert_not_called()

    def test_wildcard_alias_skipped(self):
        host = HostConfig(
            aliases=["*.example.com"],
            hostname=fv("does-not-exist.example.invalid", "hostname"),
        )
        with patch("ssh_concierge.validate.socket.getaddrinfo") as mock_gai:
            mock_gai.side_effect = socket.gaierror("should not be called")
            issues = validate_configs([(host, _meta(), set())], item_index={})
        dns_issues = [i for i in issues if "resolve" in i.message.lower()]
        assert dns_issues == []
        mock_gai.assert_not_called()

    def test_unresolved_ref_hostname_skipped(self):
        host = HostConfig(
            aliases=["server"],
            hostname=_ref("op://Vault/Item/hostname", "hostname"),
        )
        with patch("ssh_concierge.validate.socket.getaddrinfo") as mock_gai:
            mock_gai.side_effect = socket.gaierror("should not be called")
            issues = validate_configs([(host, _meta(), set())], item_index={})
        dns_issues = [i for i in issues if "resolve" in i.message.lower()]
        assert dns_issues == []
        mock_gai.assert_not_called()

    def test_proxyjump_first_hop_validated(self):
        host = HostConfig(
            aliases=["server"],
            hostname=fv("destination.example.invalid", "hostname"),
            extra_directives={"ProxyJump": fv("bastion.example.com", "ProxyJump")},
        )
        seen: list[str] = []

        def _gai(name, *_a, **_kw):
            del _a, _kw  # variadic for getaddrinfo signature, unused here
            seen.append(name)
            return [(socket.AF_INET, 0, 0, "", ("10.0.0.1", 0))]

        with patch("ssh_concierge.validate.socket.getaddrinfo", side_effect=_gai):
            validate_configs([(host, _meta(), set())], item_index={})
        # Only the ProxyJump hop should be resolved
        assert seen == ["bastion.example.com"]

    def test_proxyjump_chain_only_first_hop(self):
        host = HostConfig(
            aliases=["server"],
            hostname=fv("destination.example.invalid", "hostname"),
            extra_directives={
                "ProxyJump": fv("jump1.example.com,jump2.example.com", "ProxyJump"),
            },
        )
        seen: list[str] = []

        def _gai(name, *_a, **_kw):
            del _a, _kw  # variadic for getaddrinfo signature, unused here
            seen.append(name)
            return [(socket.AF_INET, 0, 0, "", ("10.0.0.1", 0))]

        with patch("ssh_concierge.validate.socket.getaddrinfo", side_effect=_gai):
            validate_configs([(host, _meta(), set())], item_index={})
        assert seen == ["jump1.example.com"]

    def test_proxyjump_strips_user_and_port(self):
        host = HostConfig(
            aliases=["server"],
            hostname=fv("destination.example.invalid", "hostname"),
            extra_directives={
                "ProxyJump": fv("admin@bastion.example.com:2222", "ProxyJump"),
            },
        )
        seen: list[str] = []

        def _gai(name, *_a, **_kw):
            del _a, _kw  # variadic for getaddrinfo signature, unused here
            seen.append(name)
            return [(socket.AF_INET, 0, 0, "", ("10.0.0.1", 0))]

        with patch("ssh_concierge.validate.socket.getaddrinfo", side_effect=_gai):
            validate_configs([(host, _meta(), set())], item_index={})
        assert seen == ["bastion.example.com"]


class TestValidateRefs:
    def _host_with_field_ref(self, ref: str) -> HostConfig:
        return HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            custom_fields={"website": _ref(ref, "website")},
        )

    def test_disabled_by_default_no_op_calls(self):
        host = self._host_with_field_ref("op://Other/Missing/url")
        op = MagicMock()
        validate_configs([(host, _meta(), set())], item_index={}, op=op)
        op.read.assert_not_called()

    def test_existing_item_no_issue(self):
        host = self._host_with_field_ref("op://Other/Existing/url")
        op = MagicMock()
        op.read.return_value = "Existing"  # title fetch succeeds
        issues = validate_configs(
            [(host, _meta(), set())], item_index={}, op=op, validate_refs=True
        )
        deep_issues = [
            i
            for i in issues
            if "missing" in i.message.lower() and "ref" in i.message.lower()
        ]
        assert deep_issues == []
        op.read.assert_called_once_with("op://Other/Existing/title")

    def test_missing_item_emits_issue(self):
        host = self._host_with_field_ref("op://Other/Missing/url")
        op = MagicMock()
        op.read.return_value = None  # title fetch returns None
        issues = validate_configs(
            [(host, _meta(), set())], item_index={}, op=op, validate_refs=True
        )
        deep_issues = [
            i
            for i in issues
            if "missing" in i.message.lower() and "ref" in i.message.lower()
        ]
        assert len(deep_issues) == 1
        assert "op://Other/Missing" in deep_issues[0].message

    def test_cache_hit_avoids_second_call(self):
        host_a = HostConfig(
            aliases=["a"],
            hostname=fv("127.0.0.1", "hostname"),
            custom_fields={"website": _ref("op://Other/Same/url", "website")},
        )
        host_b = HostConfig(
            aliases=["b"],
            hostname=fv("127.0.0.1", "hostname"),
            custom_fields={"docs": _ref("op://Other/Same/manual", "docs")},
        )
        op = MagicMock()
        op.read.return_value = "Same"
        validate_configs(
            [(host_a, _meta(), set()), (host_b, _meta(), set())],
            item_index={},
            op=op,
            validate_refs=True,
        )
        # Title lookup should run exactly once for the shared (vault, item) pair
        op.read.assert_called_once_with("op://Other/Same/title")

    def test_indexed_item_skipped(self):
        """Refs whose target is already in item_index need no deep lookup."""
        item = _stub_item("i1", "Existing", "Other")
        host = self._host_with_field_ref("op://Other/Existing/url")
        op = MagicMock()
        validate_configs(
            [(host, _meta(), set())],
            item_index=_index_from([item]),
            op=op,
            validate_refs=True,
        )
        op.read.assert_not_called()

    def test_sensitive_field_does_not_call_op_read(self):
        """Deep check fetches /title only — never the sensitive payload."""
        host = HostConfig(
            aliases=["server"],
            hostname=fv("127.0.0.1", "hostname"),
            password=_ref("op://Other/Item/password", "password", sensitive=True),
        )
        op = MagicMock()
        op.read.return_value = "Item"
        validate_configs(
            [(host, _meta(), set())], item_index={}, op=op, validate_refs=True
        )
        # The only call goes to /title, never to /password
        for call in op.read.call_args_list:
            args, _ = call
            assert "/password" not in args[0]
            assert "/title" in args[0]


class TestSensitiveFieldInvariant:
    def test_resolved_sensitive_raises(self, tmp_path):
        """Writing a hostdata where a sensitive field has a resolved value raises."""
        from ssh_concierge.config import generate_runtime_config

        bad_hostdata = {
            "server": {
                "fields": {
                    "password": {
                        "original": "op://V/I/password",
                        "resolved": "PLAINTEXT",
                        "sensitive": True,
                    }
                }
            }
        }

        def _kf(fp: str):
            return tmp_path / "keys" / f"{fp}.pub"

        with pytest.raises(RuntimeError, match="[Ss]ensitive"):
            generate_runtime_config(
                hosts=[],
                runtime_dir=tmp_path,
                keys_dir=tmp_path / "keys",
                hosts_file=tmp_path / "hosts.conf",
                hostdata_file=tmp_path / "hostdata.json",
                key_file=_kf,
                hostdata=bad_hostdata,
            )

    def test_sensitive_with_null_resolved_ok(self, tmp_path):
        """Sensitive field with resolved=None is accepted (rule is satisfied)."""
        from ssh_concierge.config import generate_runtime_config

        ok_hostdata = {
            "server": {
                "fields": {
                    "password": {
                        "original": "op://V/I/password",
                        "resolved": None,
                        "sensitive": True,
                    }
                }
            }
        }

        def _kf(fp: str):
            return tmp_path / "keys" / f"{fp}.pub"

        generate_runtime_config(
            hosts=[],
            runtime_dir=tmp_path,
            keys_dir=tmp_path / "keys",
            hosts_file=tmp_path / "hosts.conf",
            hostdata_file=tmp_path / "hostdata.json",
            key_file=_kf,
            hostdata=ok_hostdata,
        )
        assert (tmp_path / "hostdata.json").exists()
