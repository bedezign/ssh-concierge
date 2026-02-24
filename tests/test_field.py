"""Tests for ssh_concierge.field."""

from __future__ import annotations

from unittest.mock import patch

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


class TestResolveSingle:
    @patch('ssh_concierge.onepassword._run_op')
    def test_cache_hit_skips_op_read(self, mock_run_op):
        from ssh_concierge.field import resolve_single

        cache = {'op://v1/i1/password': 'cached-pw'}
        result = resolve_single('op://v1/i1/password', op_read_cache=cache)
        assert result == 'cached-pw'
        mock_run_op.assert_not_called()

    @patch('ssh_concierge.onepassword._run_op')
    def test_cache_hit_case_insensitive(self, mock_run_op):
        from ssh_concierge.field import resolve_single

        cache = {'op://v1/i1/url': 'workbench1.example.com'}
        result = resolve_single('op://v1/i1/URL', op_read_cache=cache)
        assert result == 'workbench1.example.com'
        mock_run_op.assert_not_called()

    @patch('ssh_concierge.onepassword._run_op')
    def test_cache_miss_calls_op_read(self, mock_run_op):
        from ssh_concierge.field import resolve_single

        mock_run_op.return_value = 'op-result\n'
        cache = {'op://v1/i1/other': 'something'}
        result = resolve_single('op://v1/i1/password', op_read_cache=cache)
        assert result == 'op-result'
        mock_run_op.assert_called_once()

    @patch('ssh_concierge.onepassword._run_op')
    def test_no_cache_calls_op_read(self, mock_run_op):
        from ssh_concierge.field import resolve_single

        mock_run_op.return_value = 'result\n'
        result = resolve_single('op://v1/i1/password')
        assert result == 'result'
        mock_run_op.assert_called_once()


class TestResolveChain:
    @patch('ssh_concierge.field.resolve_single')
    def test_single_reference_success(self, mock_resolve):
        mock_resolve.return_value = 'resolved-value'
        result = resolve_chain('op://Vault/Item/field')
        assert result == 'resolved-value'

    @patch('ssh_concierge.field.resolve_single')
    def test_single_reference_failure_returns_none(self, mock_resolve):
        mock_resolve.return_value = None
        result = resolve_chain('op://Vault/Item/field')
        assert result is None

    def test_literal_value(self):
        result = resolve_chain('10.0.0.1')
        assert result == '10.0.0.1'

    @patch('ssh_concierge.field.resolve_single')
    def test_fallback_to_literal(self, mock_resolve):
        mock_resolve.return_value = None
        result = resolve_chain('op://Vault/Item/field||10.0.0.1')
        assert result == '10.0.0.1'

    @patch('ssh_concierge.field.resolve_single')
    def test_fallback_chain_first_wins(self, mock_resolve):
        mock_resolve.return_value = 'first-value'
        result = resolve_chain('op://Vault/Item/field||fallback')
        assert result == 'first-value'
        mock_resolve.assert_called_once()

    @patch('ssh_concierge.field.resolve_single')
    def test_fallback_chain_second_ref(self, mock_resolve):
        mock_resolve.side_effect = [None, 'backup-value']
        result = resolve_chain('op://Vault/Item/field||op://Vault/Backup/field')
        assert result == 'backup-value'
        assert mock_resolve.call_count == 2

    @patch('ssh_concierge.field.resolve_single')
    def test_all_segments_fail(self, mock_resolve):
        mock_resolve.return_value = None
        result = resolve_chain('op://V/I/f1||op://V/I/f2')
        assert result is None

    @patch('ssh_concierge.field.resolve_single')
    def test_empty_segments_skipped(self, mock_resolve):
        mock_resolve.return_value = None
        result = resolve_chain('op://V/I/f||  ||fallback')
        assert result == 'fallback'

    @patch('ssh_concierge.field.resolve_single')
    def test_self_ref_expanded(self, mock_resolve):
        mock_resolve.return_value = 'pw'
        result = resolve_chain('op://./password', vault_id='v1', item_id='i1')
        mock_resolve.assert_called_once_with('op://v1/i1/password', None)
        assert result == 'pw'

    @patch('ssh_concierge.field.resolve_single')
    def test_ops_normalized(self, mock_resolve):
        mock_resolve.return_value = 'secret'
        result = resolve_chain('ops://Vault/Item/field')
        mock_resolve.assert_called_once_with('op://Vault/Item/field', None)
        assert result == 'secret'

    @patch('ssh_concierge.field.resolve_single')
    def test_incomplete_ref_gets_password_appended(self, mock_resolve):
        mock_resolve.return_value = 'pw'
        result = resolve_chain('op://Vault/Item')
        mock_resolve.assert_called_once_with('op://Vault/Item/password', None)

    @patch('ssh_concierge.field.resolve_single')
    def test_passes_cache_to_resolve_single(self, mock_resolve):
        mock_resolve.return_value = 'value'
        cache = {'op://V/I/field': 'cached'}
        result = resolve_chain('op://V/I/field', op_read_cache=cache)
        mock_resolve.assert_called_once_with('op://V/I/field', cache)


class TestFieldValue:
    def test_from_raw_literal(self):
        fv = FieldValue.from_raw('10.0.0.1', 'hostname')
        assert fv.original == '10.0.0.1'
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

    @patch('ssh_concierge.field.resolve_chain')
    def test_resolve_reference(self, mock_chain):
        mock_chain.return_value = '10.0.0.1'
        fv = FieldValue.from_raw('op://V/I/hostname', 'hostname')
        resolved = fv.resolve(vault_id='v', item_id='i')
        assert resolved.resolved == '10.0.0.1'
        mock_chain.assert_called_once_with('op://V/I/hostname', 'v', 'i', None)

    def test_resolve_literal(self):
        fv = FieldValue.from_raw('10.0.0.1', 'hostname')
        resolved = fv.resolve()
        assert resolved.resolved == '10.0.0.1'

    def test_resolve_sensitive_stays_none(self):
        fv = FieldValue.from_raw('ops://V/I/password', 'password')
        resolved = fv.resolve(vault_id='v', item_id='i')
        assert resolved.resolved is None

    def test_resolve_template(self):
        fv = FieldValue.from_raw('{{alias}}.example.com', 'hostname')
        resolved = fv.resolve()
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
