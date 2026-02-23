"""Tests for ssh_concierge.password."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from ssh_concierge.onepassword import OpError
from ssh_concierge.password import (
    ItemMeta,
    _shell_escape,
    askpass_env,
    build_op_reference,
    resolve_password,
)


class TestResolvePassword:
    def test_none_returns_none(self):
        assert resolve_password(None) is None

    def test_empty_returns_none(self):
        assert resolve_password('') is None

    def test_literal_returns_as_is(self):
        assert resolve_password('hunter2') == 'hunter2'

    def test_literal_with_special_chars(self):
        pw = 'p@ss$w0rd!#'
        assert resolve_password(pw) == pw

    @patch('ssh_concierge.onepassword._run_op')
    def test_full_op_reference(self, mock_run_op):
        mock_run_op.return_value = 'resolved-password\n'
        result = resolve_password('op://MyVault/MyItem/password')
        assert result == 'resolved-password'
        mock_run_op.assert_called_once_with(['read', 'op://MyVault/MyItem/password'])

    @patch('ssh_concierge.onepassword._run_op')
    def test_full_op_reference_with_section(self, mock_run_op):
        mock_run_op.return_value = 'secret\n'
        result = resolve_password('op://Vault/Item/Section/field')
        assert result == 'secret'
        mock_run_op.assert_called_once_with(['read', 'op://Vault/Item/Section/field'])

    @patch('ssh_concierge.onepassword._run_op')
    def test_self_reference_expands(self, mock_run_op):
        mock_run_op.return_value = 'the-password\n'
        meta = ItemMeta(vault_id='vault-abc', item_id='item-123')
        result = resolve_password('op://./password', meta)
        assert result == 'the-password'
        mock_run_op.assert_called_once_with(
            ['read', 'op://vault-abc/item-123/password']
        )

    @patch('ssh_concierge.onepassword._run_op')
    def test_self_reference_with_section(self, mock_run_op):
        mock_run_op.return_value = 'pw\n'
        meta = ItemMeta(vault_id='v1', item_id='i1')
        result = resolve_password('op://./SSH Config/password', meta)
        assert result == 'pw'
        mock_run_op.assert_called_once_with(
            ['read', 'op://v1/i1/SSH Config/password']
        )

    def test_self_reference_without_meta_returns_none(self):
        result = resolve_password('op://./password')
        assert result is None

    @patch('ssh_concierge.onepassword._run_op')
    def test_op_read_failure_returns_none(self, mock_run_op):
        mock_run_op.side_effect = OpError('not signed in')
        result = resolve_password('op://Vault/Item/field')
        assert result is None

    @patch('ssh_concierge.onepassword._run_op')
    def test_self_ref_op_read_failure_returns_none(self, mock_run_op):
        mock_run_op.side_effect = OpError('locked')
        meta = ItemMeta(vault_id='v', item_id='i')
        result = resolve_password('op://./password', meta)
        assert result is None


class TestBuildOpReference:
    def test_literal_password(self):
        meta = ItemMeta(vault_id='vault-abc', item_id='item-123')
        ref = build_op_reference('hunter2', meta, 'SSH Config')
        assert ref == 'op://vault-abc/item-123/SSH Config/password'

    def test_full_op_reference_unchanged(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = build_op_reference('op://MyVault/MyItem/password', meta, 'SSH Config')
        assert ref == 'op://MyVault/MyItem/password'

    def test_full_op_reference_with_section(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = build_op_reference('op://Vault/Item/Section/field', meta, 'SSH Config')
        assert ref == 'op://Vault/Item/Section/field'

    def test_self_reference(self):
        meta = ItemMeta(vault_id='vault-abc', item_id='item-123')
        ref = build_op_reference('op://./password', meta, 'SSH Config')
        assert ref == 'op://vault-abc/item-123/password'

    def test_self_reference_with_section(self):
        meta = ItemMeta(vault_id='v1', item_id='i1')
        ref = build_op_reference('op://./SSH Config/password', meta, 'SSH Config')
        assert ref == 'op://v1/i1/SSH Config/password'

    def test_named_section(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = build_op_reference('literal-pw', meta, 'SSH Config: prod')
        assert ref == 'op://v/i/SSH Config: prod/password'

    def test_incomplete_op_reference_appends_password(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = build_op_reference('op://MyVault/MyLogin', meta, 'SSH Config')
        assert ref == 'op://MyVault/MyLogin/password'

    def test_incomplete_op_reference_simple(self):
        meta = ItemMeta(vault_id='v', item_id='i')
        ref = build_op_reference('op://Vault/Item', meta, 'SSH Config')
        assert ref == 'op://Vault/Item/password'


class TestAskpassEnv:
    def test_yields_correct_env_vars(self):
        with askpass_env('mypassword') as env:
            assert 'SSH_ASKPASS' in env
            assert env['SSH_ASKPASS_REQUIRE'] == 'force'
            script = Path(env['SSH_ASKPASS'])
            assert script.exists()
            assert script.stat().st_mode & stat.S_IRWXU == stat.S_IRWXU

    def test_script_echoes_password(self):
        with askpass_env('testpw123') as env:
            content = Path(env['SSH_ASKPASS']).read_text()
            assert 'echo "testpw123"' in content

    def test_cleans_up_on_exit(self):
        with askpass_env('pw') as env:
            script_path = env['SSH_ASKPASS']
            assert Path(script_path).exists()
        assert not Path(script_path).exists()

    def test_password_with_special_chars(self):
        with askpass_env('p@ss"w$rd`test\\') as env:
            content = Path(env['SSH_ASKPASS']).read_text()
            # Verify escaping
            assert '\\"' in content
            assert '\\$' in content
            assert '\\`' in content
            assert '\\\\' in content


class TestShellEscape:
    def test_backslash(self):
        assert _shell_escape('a\\b') == 'a\\\\b'

    def test_double_quote(self):
        assert _shell_escape('a"b') == 'a\\"b'

    def test_dollar(self):
        assert _shell_escape('$var') == '\\$var'

    def test_backtick(self):
        assert _shell_escape('`cmd`') == '\\`cmd\\`'

    def test_no_special_chars(self):
        assert _shell_escape('plain') == 'plain'

    def test_combined(self):
        assert _shell_escape('a"b$c\\d`e') == 'a\\"b\\$c\\\\d\\`e'
