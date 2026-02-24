"""Tests for ssh_concierge.field."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ssh_concierge.field import (
    FieldValue,
    classify_type,
    expand_self_ref,
    is_sensitive,
    normalize_incomplete_ref,
    normalize_original,
    normalize_segment,
    resolve_chain,
)
from ssh_concierge.onepassword import OpError


class TestClassifyType:
    def test_literal(self):
        assert classify_type('10.0.0.1') == 'literal'

    def test_literal_plain_text(self):
        assert classify_type('deploy') == 'literal'

    def test_reference_op(self):
        assert classify_type('op://Vault/Item/field') == 'reference'

    def test_reference_ops(self):
        assert classify_type('ops://Vault/Item/field') == 'reference'

    def test_reference_self(self):
        assert classify_type('op://./password') == 'reference'

    def test_reference_with_fallback(self):
        assert classify_type('op://./pw||fallback') == 'reference'

    def test_template(self):
        assert classify_type('{{alias}}.example.com') == 'template'

    def test_template_without_reference(self):
        assert classify_type('{{alias}}') == 'template'

    def test_reference_takes_precedence_over_template(self):
        # If both :// and {{ are present, reference wins (checked first)
        assert classify_type('op://./{{alias}}') == 'reference'


class TestIsSensitive:
    def test_password_field_name(self):
        assert is_sensitive('anything', 'password') is True

    def test_passwd_field_name(self):
        assert is_sensitive('anything', 'passwd') is True

    def test_pass_field_name(self):
        assert is_sensitive('anything', 'pass') is True

    def test_secret_field_name(self):
        assert is_sensitive('anything', 'secret') is True

    def test_token_field_name(self):
        assert is_sensitive('anything', 'token') is True

    def test_case_insensitive_field_name(self):
        assert is_sensitive('anything', 'Password') is True
        assert is_sensitive('anything', 'TOKEN') is True

    def test_substring_match(self):
        assert is_sensitive('anything', 'sudo_password') is True
        assert is_sensitive('anything', 'api_token') is True
        assert is_sensitive('anything', 'my_secret_field') is True

    def test_ops_prefix(self):
        assert is_sensitive('ops://Vault/Item/field', 'hostname') is True

    def test_ops_in_chain(self):
        assert is_sensitive('op://./pw||ops://Vault/Backup/pw', 'api_key') is True

    def test_non_sensitive_field(self):
        assert is_sensitive('10.0.0.1', 'hostname') is False

    def test_op_reference_non_sensitive_name(self):
        assert is_sensitive('op://Vault/Item/hostname', 'hostname') is False

    def test_user_field_not_sensitive(self):
        assert is_sensitive('deploy', 'user') is False


class TestNormalizeSegment:
    def test_ops_to_op(self):
        assert normalize_segment('ops://Vault/Item/field') == 'op://Vault/Item/field'

    def test_op_unchanged(self):
        assert normalize_segment('op://Vault/Item/field') == 'op://Vault/Item/field'

    def test_literal_unchanged(self):
        assert normalize_segment('10.0.0.1') == '10.0.0.1'

    def test_only_first_ops_replaced(self):
        # Unlikely but test the boundary
        assert normalize_segment('ops://Vault/ops://other') == 'op://Vault/ops://other'


class TestExpandSelfRef:
    def test_self_ref(self):
        result = expand_self_ref('op://./password', 'vault-abc', 'item-123')
        assert result == 'op://vault-abc/item-123/password'

    def test_self_ref_with_section(self):
        result = expand_self_ref('op://./SSH Config/password', 'v1', 'i1')
        assert result == 'op://v1/i1/SSH Config/password'

    def test_full_ref_unchanged(self):
        result = expand_self_ref('op://Vault/Item/field', 'v', 'i')
        assert result == 'op://Vault/Item/field'

    def test_literal_unchanged(self):
        result = expand_self_ref('literal', 'v', 'i')
        assert result == 'literal'


class TestNormalizeIncompleteRef:
    def test_incomplete_appends_password(self):
        assert normalize_incomplete_ref('op://Vault/Item') == 'op://Vault/Item/password'

    def test_complete_unchanged(self):
        assert normalize_incomplete_ref('op://Vault/Item/field') == 'op://Vault/Item/field'

    def test_with_section_unchanged(self):
        assert normalize_incomplete_ref('op://Vault/Item/Section/field') == 'op://Vault/Item/Section/field'

    def test_non_op_unchanged(self):
        assert normalize_incomplete_ref('literal') == 'literal'


class TestNormalizeOriginal:
    def test_self_ref_expanded(self):
        result = normalize_original('op://./password', 'v1', 'i1')
        assert result == 'op://v1/i1/password'

    def test_self_ref_with_section(self):
        result = normalize_original('op://./SSH Config/password', 'v1', 'i1')
        assert result == 'op://v1/i1/SSH Config/password'

    def test_ops_self_ref_expanded(self):
        result = normalize_original('ops://./password', 'v1', 'i1')
        assert result == 'ops://v1/i1/password'

    def test_full_ref_unchanged(self):
        result = normalize_original('op://Vault/Item/field', 'v1', 'i1')
        assert result == 'op://Vault/Item/field'

    def test_literal_unchanged(self):
        result = normalize_original('10.0.0.1', 'v1', 'i1')
        assert result == '10.0.0.1'

    def test_chain_with_self_ref(self):
        result = normalize_original('op://./pw||op://Vault/Backup/pw', 'v1', 'i1')
        assert result == 'op://v1/i1/pw||op://Vault/Backup/pw'

    def test_chain_with_literal_fallback(self):
        result = normalize_original('op://./hostname||10.0.0.1', 'v1', 'i1')
        assert result == 'op://v1/i1/hostname||10.0.0.1'

    def test_incomplete_ref_gets_password(self):
        result = normalize_original('op://Vault/Item', 'v1', 'i1')
        assert result == 'op://Vault/Item/password'

    def test_ops_self_ref_in_chain(self):
        result = normalize_original('ops://./secret||ops://./backup_secret', 'v1', 'i1')
        assert result == 'ops://v1/i1/secret||ops://v1/i1/backup_secret'


def _mock_op(**kwargs) -> MagicMock:
    """Create a mock OnePassword instance."""
    op = MagicMock()
    op.read = MagicMock(**kwargs)
    return op


class TestResolveChain:
    def test_single_reference_success(self):
        op = _mock_op(return_value='resolved-value')
        result = resolve_chain('op://Vault/Item/field', op)
        assert result == 'resolved-value'

    def test_single_reference_failure_returns_none(self):
        op = _mock_op(return_value=None)
        result = resolve_chain('op://Vault/Item/field', op)
        assert result is None

    def test_literal_value(self):
        op = _mock_op()
        result = resolve_chain('10.0.0.1', op)
        assert result == '10.0.0.1'
        op.read.assert_not_called()

    def test_fallback_to_literal(self):
        op = _mock_op(return_value=None)
        result = resolve_chain('op://Vault/Item/field||10.0.0.1', op)
        assert result == '10.0.0.1'

    def test_fallback_chain_first_wins(self):
        op = _mock_op(return_value='first-value')
        result = resolve_chain('op://Vault/Item/field||fallback', op)
        assert result == 'first-value'
        op.read.assert_called_once()

    def test_fallback_chain_second_ref(self):
        op = _mock_op(side_effect=[None, 'backup-value'])
        result = resolve_chain('op://Vault/Item/field||op://Vault/Backup/field', op)
        assert result == 'backup-value'
        assert op.read.call_count == 2

    def test_all_segments_fail(self):
        op = _mock_op(return_value=None)
        result = resolve_chain('op://V/I/f1||op://V/I/f2', op)
        assert result is None

    def test_empty_segments_skipped(self):
        op = _mock_op(return_value=None)
        result = resolve_chain('op://V/I/f||  ||fallback', op)
        assert result == 'fallback'

    def test_self_ref_expanded(self):
        op = _mock_op(return_value='pw')
        result = resolve_chain('op://./password', op, vault_id='v1', item_id='i1')
        op.read.assert_called_once_with('op://v1/i1/password', cache_only=False)
        assert result == 'pw'

    def test_ops_normalized(self):
        op = _mock_op(return_value='secret')
        result = resolve_chain('ops://Vault/Item/field', op)
        op.read.assert_called_once_with('op://Vault/Item/field', cache_only=False)
        assert result == 'secret'

    def test_incomplete_ref_gets_password_appended(self):
        op = _mock_op(return_value='pw')
        resolve_chain('op://Vault/Item', op)
        op.read.assert_called_once_with('op://Vault/Item/password', cache_only=False)


class TestFieldValue:
    def test_from_raw_literal(self):
        fv = FieldValue.from_raw('10.0.0.1', 'hostname')
        assert fv.original == '10.0.0.1'
        assert fv.raw == '10.0.0.1'
        assert fv.resolved is None
        assert fv.sensitive is False
        assert fv.field_type == 'literal'

    def test_from_raw_reference(self):
        fv = FieldValue.from_raw('op://Vault/Item/hostname', 'hostname')
        assert fv.field_type == 'reference'
        assert fv.sensitive is False

    def test_from_raw_sensitive_by_name(self):
        fv = FieldValue.from_raw('op://Vault/Item/password', 'password')
        assert fv.sensitive is True

    def test_from_raw_sensitive_by_ops(self):
        fv = FieldValue.from_raw('ops://Vault/Item/field', 'hostname')
        assert fv.sensitive is True

    def test_from_raw_template(self):
        fv = FieldValue.from_raw('{{alias}}.example.com', 'hostname')
        assert fv.field_type == 'template'
        assert fv.sensitive is False

    def test_with_resolved(self):
        fv = FieldValue.from_raw('10.0.0.1', 'hostname')
        fv2 = fv.with_resolved('10.0.0.1')
        assert fv2.resolved == '10.0.0.1'
        assert fv2.original == '10.0.0.1'

    def test_for_config_non_sensitive(self):
        fv = FieldValue(original='op://V/I/f', resolved='10.0.0.1', sensitive=False, field_type='reference')
        assert fv.for_config() == '10.0.0.1'

    def test_for_config_sensitive_returns_none(self):
        fv = FieldValue(original='ops://V/I/pw', resolved=None, sensitive=True, field_type='reference')
        assert fv.for_config() is None

    def test_for_config_unresolved_returns_none(self):
        fv = FieldValue(original='op://V/I/f', resolved=None, sensitive=False, field_type='reference')
        assert fv.for_config() is None

    def test_needs_resolution_no_cache(self):
        fv = FieldValue.from_raw('op://V/I/f', 'hostname')
        assert fv.needs_resolution(None) is True

    def test_needs_resolution_same_original(self):
        fv = FieldValue.from_raw('op://V/I/f', 'hostname')
        cached = FieldValue(original='op://V/I/f', resolved='10.0.0.1', sensitive=False, field_type='reference')
        assert fv.needs_resolution(cached) is False

    def test_needs_resolution_different_original(self):
        fv = FieldValue.from_raw('op://V/I/f2', 'hostname')
        cached = FieldValue(original='op://V/I/f', resolved='10.0.0.1', sensitive=False, field_type='reference')
        assert fv.needs_resolution(cached) is True

    def test_resolve_reference(self):
        op = _mock_op(return_value='10.0.0.1')
        fv = FieldValue.from_raw('op://V/I/hostname', 'hostname')
        resolved = fv.resolve(op, vault_id='v', item_id='i')
        assert resolved.resolved == '10.0.0.1'

    def test_resolve_literal(self):
        op = _mock_op()
        fv = FieldValue.from_raw('10.0.0.1', 'hostname')
        resolved = fv.resolve(op)
        assert resolved.resolved == '10.0.0.1'
        op.read.assert_not_called()

    def test_resolve_sensitive_stays_none(self):
        op = _mock_op()
        fv = FieldValue.from_raw('ops://V/I/password', 'password')
        resolved = fv.resolve(op, vault_id='v', item_id='i')
        assert resolved.resolved is None
        op.read.assert_not_called()

    def test_resolve_template(self):
        op = _mock_op()
        fv = FieldValue.from_raw('{{alias}}.example.com', 'hostname')
        resolved = fv.resolve(op)
        assert resolved.resolved == '{{alias}}.example.com'

    def test_to_hostdata(self):
        fv = FieldValue(original='op://V/I/f', resolved='10.0.0.1', sensitive=False, field_type='reference')
        data = fv.to_hostdata()
        assert data == {'original': 'op://V/I/f', 'resolved': '10.0.0.1', 'sensitive': False}

    def test_to_hostdata_sensitive(self):
        fv = FieldValue(original='ops://V/I/pw', resolved=None, sensitive=True, field_type='reference')
        data = fv.to_hostdata()
        assert data == {'original': 'ops://V/I/pw', 'resolved': None, 'sensitive': True}

    def test_from_hostdata(self):
        data = {'original': 'op://V/I/f', 'resolved': '10.0.0.1', 'sensitive': False}
        fv = FieldValue.from_hostdata(data, 'hostname')
        assert fv.original == 'op://V/I/f'
        assert fv.resolved == '10.0.0.1'
        assert fv.sensitive is False
        assert fv.field_type == 'reference'

    def test_from_hostdata_sensitive(self):
        data = {'original': 'ops://V/I/pw', 'resolved': None, 'sensitive': True}
        fv = FieldValue.from_hostdata(data, 'password')
        assert fv.sensitive is True
        assert fv.resolved is None

    def test_from_hostdata_roundtrip(self):
        original = FieldValue(original='op://V/I/f||fallback', resolved='fallback', sensitive=False, field_type='reference')
        data = original.to_hostdata()
        restored = FieldValue.from_hostdata(data, 'hostname')
        assert restored.original == original.original
        assert restored.resolved == original.resolved
        assert restored.sensitive == original.sensitive
