"""Tests for ssh_concierge.password."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ssh_concierge.onepassword import OnePassword, OpError
from ssh_concierge.password import (
    ItemMeta,
    create_askpass,
    normalize_reference,
    resolve_password,
)


def _mock_op(**kwargs) -> MagicMock:
    """Create a mock OnePassword instance."""
    op = MagicMock(spec=OnePassword)
    op.read = MagicMock(**kwargs)
    return op


class TestResolvePassword:
    def test_none_returns_none(self):
        op = _mock_op()
        assert resolve_password(None, op) is None

    def test_empty_returns_none(self):
        op = _mock_op()
        assert resolve_password('', op) is None

    def test_literal_returns_as_is(self):
        op = _mock_op()
        assert resolve_password('hunter2', op) == 'hunter2'

    def test_literal_with_special_chars(self):
        op = _mock_op()
        pw = 'p@ss$w0rd!#'
        assert resolve_password(pw, op) == pw

    def test_full_op_reference(self):
        op = _mock_op(return_value='resolved-password')
        result = resolve_password('op://MyVault/MyItem/password', op)
        assert result == 'resolved-password'

    def test_full_op_reference_with_section(self):
        op = _mock_op(return_value='secret')
        result = resolve_password('op://Vault/Item/Section/field', op)
        assert result == 'secret'

    def test_self_reference_expands(self):
        op = _mock_op(return_value='the-password')
        meta = ItemMeta(vault_id='vault-abc', item_id='item-123')
        result = resolve_password('op://./password', op, meta)
        assert result == 'the-password'
        op.read.assert_called_once_with('op://vault-abc/item-123/password', cache_only=False)

    def test_self_reference_with_section(self):
        op = _mock_op(return_value='pw')
        meta = ItemMeta(vault_id='v1', item_id='i1')
        result = resolve_password('op://./SSH Config/password', op, meta)
        assert result == 'pw'
        op.read.assert_called_once_with('op://v1/i1/SSH Config/password', cache_only=False)

    def test_self_reference_without_meta_returns_none(self):
        op = _mock_op()
        result = resolve_password('op://./password', op)
        assert result is None

    def test_ops_prefix_normalized_to_op(self):
        op = _mock_op(return_value='secret')
        result = resolve_password('ops://Vault/Item/password', op)
        assert result == 'secret'
        op.read.assert_called_once_with('op://Vault/Item/password', cache_only=False)

    def test_op_read_failure_returns_none(self):
        op = _mock_op(return_value=None)
        result = resolve_password('op://Vault/Item/field', op)
        assert result is None

    def test_self_ref_op_read_failure_returns_none(self):
        op = _mock_op(return_value=None)
        meta = ItemMeta(vault_id='v', item_id='i')
        result = resolve_password('op://./password', op, meta)
        assert result is None


class TestNormalizeReferenceCompat:
    def test_literal_password(self):
        meta = ItemMeta(vault_id='vault-abc', item_id='item-123')
        ref = normalize_reference('hunter2', meta, 'SSH Config')
        assert ref == 'op://vault-abc/item-123/SSH Config/password'

    def test_full_op_reference_unchanged(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = normalize_reference('op://MyVault/MyItem/password', meta, 'SSH Config')
        assert ref == 'op://MyVault/MyItem/password'

    def test_full_op_reference_with_section(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = normalize_reference('op://Vault/Item/Section/field', meta, 'SSH Config')
        assert ref == 'op://Vault/Item/Section/field'

    def test_self_reference(self):
        meta = ItemMeta(vault_id='vault-abc', item_id='item-123')
        ref = normalize_reference('op://./password', meta, 'SSH Config')
        assert ref == 'op://vault-abc/item-123/password'

    def test_self_reference_with_section(self):
        meta = ItemMeta(vault_id='v1', item_id='i1')
        ref = normalize_reference('op://./SSH Config/password', meta, 'SSH Config')
        assert ref == 'op://v1/i1/SSH Config/password'

    def test_named_section(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = normalize_reference('literal-pw', meta, 'SSH Config: prod')
        assert ref == 'op://v/i/SSH Config: prod/password'

    def test_incomplete_op_reference_appends_password(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = normalize_reference('op://MyVault/MyLogin', meta, 'SSH Config')
        assert ref == 'op://MyVault/MyLogin/password'

    def test_incomplete_op_reference_simple(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = normalize_reference('op://Vault/Item', meta, 'SSH Config')
        assert ref == 'op://Vault/Item/password'


class TestNormalizeReference:
    def test_literal_password(self):
        meta = ItemMeta(vault_id='vault-abc', item_id='item-123')
        ref = normalize_reference('hunter2', meta, 'SSH Config')
        assert ref == 'op://vault-abc/item-123/SSH Config/password'

    def test_full_op_reference_unchanged(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = normalize_reference('op://MyVault/MyItem/password', meta, 'SSH Config')
        assert ref == 'op://MyVault/MyItem/password'

    def test_self_reference(self):
        meta = ItemMeta(vault_id='vault-abc', item_id='item-123')
        ref = normalize_reference('op://./password', meta, 'SSH Config')
        assert ref == 'op://vault-abc/item-123/password'

    def test_incomplete_appends_password(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = normalize_reference('op://Vault/Item', meta, 'SSH Config')
        assert ref == 'op://Vault/Item/password'


class TestResolvePasswordFallbackChain:
    def test_fallback_chain(self):
        op = _mock_op(side_effect=[None, 'backup-pw'])
        result = resolve_password('op://V/I/pw||op://V/Backup/pw', op)
        assert result == 'backup-pw'

    def test_fallback_to_literal(self):
        op = _mock_op(return_value=None)
        result = resolve_password('op://V/I/pw||default-password', op)
        assert result == 'default-password'


class TestCreateAskpass:
    def test_returns_correct_env_vars(self):
        env = create_askpass('mypassword')
        try:
            assert 'SSH_ASKPASS' in env
            assert env['SSH_ASKPASS_REQUIRE'] == 'force'
            script = Path(env['SSH_ASKPASS'])
            assert script.exists()
            assert script.stat().st_mode & stat.S_IRWXU == stat.S_IRWXU
        finally:
            Path(env['SSH_ASKPASS']).unlink(missing_ok=True)

    def test_script_outputs_password(self):
        env = create_askpass('testpw123')
        try:
            content = Path(env['SSH_ASKPASS']).read_text()
            assert 'testpw123' in content
        finally:
            Path(env['SSH_ASKPASS']).unlink(missing_ok=True)

    def test_script_self_deletes(self):
        """Script deletes itself when executed."""
        import subprocess

        env = create_askpass('pw')
        script_path = env['SSH_ASKPASS']
        assert Path(script_path).exists()
        subprocess.run([script_path], capture_output=True)
        assert not Path(script_path).exists()

    def test_password_with_special_chars(self):
        """Heredoc approach handles all special chars without escaping."""
        pw = 'p@ss"w$rd`test\\'
        env = create_askpass(pw)
        try:
            content = Path(env['SSH_ASKPASS']).read_text()
            assert pw in content
        finally:
            Path(env['SSH_ASKPASS']).unlink(missing_ok=True)

    def test_password_with_dollar_and_backtick(self):
        """Verify shell metacharacters are preserved literally."""
        import subprocess

        pw = '$HOME `whoami` "quoted" \\backslash'
        env = create_askpass(pw)
        result = subprocess.run(
            [env['SSH_ASKPASS']],
            capture_output=True,
            text=True,
        )
        assert result.stdout.rstrip('\n') == pw
        # Script should have self-deleted
        assert not Path(env['SSH_ASKPASS']).exists()
