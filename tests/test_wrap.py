"""Tests for ssh_concierge.wrap."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ssh_concierge.wrap import (
    _run_with_askpass,
    find_real_binary,
    lookup_reference,
    main,
    resolve_via_op_read,
)


class TestFindRealBinary:
    def test_finds_ssh_in_path(self, tmp_path: Path):
        # Create a fake ssh binary
        ssh_bin = tmp_path / 'ssh'
        ssh_bin.write_text('#!/bin/sh\n')
        ssh_bin.chmod(0o755)

        with patch.dict(os.environ, {'PATH': str(tmp_path)}):
            with patch('sys.argv', ['/other/path/ssh']):
                result = find_real_binary('ssh')
                assert result == str(ssh_bin)

    def test_skips_wrapper_itself(self, tmp_path: Path):
        # Create wrapper and real binary in different dirs
        wrapper_dir = tmp_path / 'wrapper'
        real_dir = tmp_path / 'real'
        wrapper_dir.mkdir()
        real_dir.mkdir()

        wrapper = wrapper_dir / 'ssh'
        wrapper.write_text('#!/bin/sh\n# wrapper')
        wrapper.chmod(0o755)

        real = real_dir / 'ssh'
        real.write_text('#!/bin/sh\n# real')
        real.chmod(0o755)

        path = f'{wrapper_dir}{os.pathsep}{real_dir}'
        with patch.dict(os.environ, {'PATH': path}):
            with patch('sys.argv', [str(wrapper)]):
                result = find_real_binary('ssh')
                assert result == str(real)

    def test_returns_none_when_not_found(self, tmp_path: Path):
        with patch.dict(os.environ, {'PATH': str(tmp_path)}):
            with patch('sys.argv', ['/some/ssh']):
                assert find_real_binary('ssh') is None


class TestLookupReference:
    def test_found(self, tmp_path: Path):
        pw_file = tmp_path / 'passwords.json'
        pw_file.write_text(json.dumps({'myhost': 'op://vault/item/password'}))
        assert lookup_reference('myhost', pw_file) == 'op://vault/item/password'

    def test_not_found(self, tmp_path: Path):
        pw_file = tmp_path / 'passwords.json'
        pw_file.write_text(json.dumps({'other': 'op://vault/item/password'}))
        assert lookup_reference('myhost', pw_file) is None

    def test_file_missing(self, tmp_path: Path):
        assert lookup_reference('myhost', tmp_path / 'nope.json') is None

    def test_bad_json(self, tmp_path: Path):
        pw_file = tmp_path / 'passwords.json'
        pw_file.write_text('not json')
        assert lookup_reference('myhost', pw_file) is None


class TestResolveViaOpRead:
    @patch('ssh_concierge.onepassword._run_op')
    def test_success(self, mock_run_op):
        mock_run_op.return_value = 'the-password\n'
        assert resolve_via_op_read('op://vault/item/pw') == 'the-password'
        mock_run_op.assert_called_once_with(['read', 'op://vault/item/pw'])

    @patch('ssh_concierge.onepassword._run_op')
    def test_failure_returns_none(self, mock_run_op):
        from ssh_concierge.onepassword import OpError

        mock_run_op.side_effect = OpError('locked')
        assert resolve_via_op_read('op://vault/item/pw') is None


class TestRunWithAskpass:
    @patch('ssh_concierge.wrap.subprocess.run')
    def test_calls_binary_with_askpass(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        rc = _run_with_askpass('/usr/bin/ssh', 'ssh', ['-v', 'myhost'], 'secret')
        assert rc == 0

        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert cmd[0] == '/usr/bin/ssh'
        assert '-v' in cmd
        assert 'myhost' in cmd

        env = call_args[1]['env']
        assert 'SSH_ASKPASS' in env
        assert env['SSH_ASKPASS_REQUIRE'] == 'force'

    @patch('ssh_concierge.wrap.subprocess.run')
    def test_returns_exit_code(self, mock_run):
        mock_run.return_value = MagicMock(returncode=255)
        rc = _run_with_askpass('/usr/bin/ssh', 'ssh', ['myhost'], 'pw')
        assert rc == 255


class TestMain:
    @patch('ssh_concierge.wrap.os.execv')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_no_password_falls_through(self, mock_find, mock_execv, tmp_path: Path):
        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap._default_runtime_dir', return_value=tmp_path):
                main()
        mock_execv.assert_called_once_with('/usr/bin/ssh', ['ssh', 'myhost'])

    @patch('ssh_concierge.wrap._run_with_askpass', return_value=0)
    @patch('ssh_concierge.wrap.resolve_via_op_read', return_value='secret123')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_with_password(self, mock_find, mock_resolve, mock_run, tmp_path: Path):
        pw_file = tmp_path / 'passwords.json'
        pw_file.write_text(json.dumps({'myhost': 'op://v/i/pw'}))

        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap._default_runtime_dir', return_value=tmp_path):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

        mock_resolve.assert_called_once_with('op://v/i/pw')
        mock_run.assert_called_once_with('/usr/bin/ssh', 'ssh', ['myhost'], 'secret123')

    def test_no_real_binary_exits(self):
        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap.find_real_binary', return_value=None):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    @patch('ssh_concierge.wrap.os.execv')
    @patch('ssh_concierge.wrap.resolve_via_op_read', return_value=None)
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_op_read_fails_falls_through(self, mock_find, mock_resolve, mock_execv, tmp_path: Path):
        pw_file = tmp_path / 'passwords.json'
        pw_file.write_text(json.dumps({'myhost': 'op://v/i/pw'}))

        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap._default_runtime_dir', return_value=tmp_path):
                main()
        mock_execv.assert_called_once_with('/usr/bin/ssh', ['ssh', 'myhost'])

    @patch('ssh_concierge.wrap.os.execv')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/scp')
    def test_scp_tool_detection(self, mock_find, mock_execv, tmp_path: Path):
        with patch('sys.argv', ['/home/user/.local/bin/scp', 'myhost:/file', '.']):
            with patch('ssh_concierge.wrap._default_runtime_dir', return_value=tmp_path):
                main()
        mock_execv.assert_called_once_with('/usr/bin/scp', ['scp', 'myhost:/file', '.'])

    @patch('ssh_concierge.wrap.os.execv')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_no_args_passes_through(self, mock_find, mock_execv, tmp_path: Path):
        with patch('sys.argv', ['/home/user/.local/bin/ssh']):
            with patch('ssh_concierge.wrap._default_runtime_dir', return_value=tmp_path):
                main()
        mock_execv.assert_called_once_with('/usr/bin/ssh', ['ssh'])
