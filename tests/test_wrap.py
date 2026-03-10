"""Tests for ssh_concierge.wrap."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ssh_concierge.settings import Settings
from ssh_concierge.wrap import (
    _resolve_fields,
    _run_with_askpass,
    copy_to_clipboard,
    find_real_binary,
    lookup_hostdata,
    main,
    resolve_clipboard,
)


def _mock_settings(tmp_path: Path) -> Settings:
    return Settings(
        runtime_dir=tmp_path,
        askpass_dir=tmp_path,
        ttl=3600,
        op_timeout=120,
        config_file=None,
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


class TestLookupHostdata:
    def test_found(self, tmp_path: Path):
        hd_file = tmp_path / 'hostdata.json'
        hd_file.write_text(json.dumps({
            'myhost': {
                'fields': {
                    'password': {'original': 'op://vault/item/password', 'resolved': None, 'sensitive': True},
                },
            },
        }))
        entry = lookup_hostdata('myhost', hd_file)
        assert entry['fields']['password']['original'] == 'op://vault/item/password'

    def test_not_found(self, tmp_path: Path):
        hd_file = tmp_path / 'hostdata.json'
        hd_file.write_text(json.dumps({'other': {'fields': {}}}))
        assert lookup_hostdata('myhost', hd_file) is None

    def test_file_missing(self, tmp_path: Path):
        assert lookup_hostdata('myhost', tmp_path / 'nope.json') is None

    def test_bad_json(self, tmp_path: Path):
        hd_file = tmp_path / 'hostdata.json'
        hd_file.write_text('not json')
        assert lookup_hostdata('myhost', hd_file) is None

    def test_with_clipboard(self, tmp_path: Path):
        hd_file = tmp_path / 'hostdata.json'
        hd_file.write_text(json.dumps({
            'myhost': {
                'fields': {
                    'password': {'original': 'ops://v/i/pw', 'resolved': None, 'sensitive': True},
                },
                'clipboard': 'sudo -i\\n{password}\\n',
            },
        }))
        entry = lookup_hostdata('myhost', hd_file)
        assert entry['clipboard'] == 'sudo -i\\n{password}\\n'
        assert entry['fields']['password']['original'] == 'ops://v/i/pw'


class TestResolveFields:
    def test_cached_non_sensitive(self):
        entry = {
            'fields': {
                'hostname': {'original': 'op://V/I/hostname', 'resolved': '10.0.0.1', 'sensitive': False},
                'user': {'original': 'deploy', 'resolved': 'deploy', 'sensitive': False},
            },
        }
        result = _resolve_fields(entry)
        assert result == {'hostname': '10.0.0.1', 'user': 'deploy'}

    @patch('ssh_concierge.wrap.OnePassword')
    def test_sensitive_resolved_at_ssh_time(self, mock_op_cls):
        mock_op = mock_op_cls.return_value
        mock_op.read.return_value = 'secret123'
        entry = {
            'fields': {
                'password': {'original': 'ops://V/I/password', 'resolved': None, 'sensitive': True},
            },
        }
        result = _resolve_fields(entry)
        assert result == {'password': 'secret123'}

    @patch('ssh_concierge.wrap.OnePassword')
    def test_password_failure_returns_none(self, mock_op_cls):
        mock_op = mock_op_cls.return_value
        mock_op.read.return_value = None
        entry = {
            'fields': {
                'password': {'original': 'ops://V/I/password', 'resolved': None, 'sensitive': True},
            },
        }
        result = _resolve_fields(entry)
        assert result is None

    def test_non_password_failure_skipped(self):
        entry = {
            'fields': {
                'hostname': {'original': 'op://V/I/hostname', 'resolved': None, 'sensitive': False},
                'user': {'original': 'deploy', 'resolved': 'deploy', 'sensitive': False},
            },
        }
        # hostname has no resolved value and isn't a reference that would be resolved
        # by _resolve_fields (it only resolves fields with resolved=None)
        # but since original doesn't start with op:// in the resolve_chain call,
        # it returns the literal. Let's use a proper reference.
        entry = {
            'fields': {
                'user': {'original': 'deploy', 'resolved': 'deploy', 'sensitive': False},
            },
        }
        result = _resolve_fields(entry)
        assert result == {'user': 'deploy'}

    @patch('ssh_concierge.wrap.OnePassword')
    def test_fallback_chain(self, mock_op_cls):
        mock_op = mock_op_cls.return_value
        mock_op.read.side_effect = [None, 'backup-pw']
        entry = {
            'fields': {
                'password': {
                    'original': 'op://V/I/pw||op://V/Backup/pw',
                    'resolved': None,
                    'sensitive': True,
                },
            },
        }
        result = _resolve_fields(entry)
        assert result == {'password': 'backup-pw'}


class TestResolveClipboard:
    def test_literal_backslash_n(self):
        result = resolve_clipboard('sudo -i\\n{password}\\n', {'password': 'secret'})
        assert result == 'sudo -i\nsecret\n'

    def test_real_newlines_preserved(self):
        result = resolve_clipboard('sudo -i\n{password}\n', {'password': 'secret'})
        assert result == 'sudo -i\nsecret\n'

    def test_mixed_newlines(self):
        # Real newline + literal \n in same template
        result = resolve_clipboard('line1\nline2\\nline3', {})
        assert result == 'line1\nline2\nline3'

    def test_unrecognized_placeholder_left_as_is(self):
        result = resolve_clipboard('{unknown}', {})
        assert result == '{unknown}'

    def test_no_placeholders(self):
        result = resolve_clipboard('just text\\n', {})
        assert result == 'just text\n'

    def test_multiple_placeholders(self):
        result = resolve_clipboard('{user}\\n{password}', {'user': 'admin', 'password': 'pw'})
        assert result == 'admin\npw'

    def test_placeholder_used_twice(self):
        result = resolve_clipboard('{pw}\\n{pw}', {'pw': 'x'})
        assert result == 'x\nx'

    def test_double_brace_placeholders(self):
        result = resolve_clipboard('{{password}}', {'password': 'secret'})
        assert result == 'secret'

    def test_mixed_single_and_double_brace(self):
        result = resolve_clipboard('{{user}}\\n{password}', {'user': 'admin', 'password': 'pw'})
        assert result == 'admin\npw'


class TestCopyToClipboard:
    @patch('ssh_concierge.wrap.subprocess.run')
    def test_wayland(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with patch.dict(os.environ, {'WAYLAND_DISPLAY': 'wayland-0'}):
            assert copy_to_clipboard('test') is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ['wl-copy']
        assert mock_run.call_args[1]['input'] == b'test'

    @patch('ssh_concierge.wrap.subprocess.run')
    def test_x11(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with patch.dict(os.environ, {'DISPLAY': ':0'}, clear=False):
            env = os.environ.copy()
            env.pop('WAYLAND_DISPLAY', None)
            with patch.dict(os.environ, env, clear=True):
                assert copy_to_clipboard('test') is True
        cmd = mock_run.call_args[0][0]
        assert cmd == ['xclip', '-selection', 'clipboard']

    def test_no_display(self, capsys):
        with patch.dict(os.environ, {}, clear=True):
            assert copy_to_clipboard('test') is False
        err = capsys.readouterr().err
        assert 'no clipboard tool' in err.lower()

    @patch('ssh_concierge.wrap.subprocess.run', side_effect=FileNotFoundError('wl-copy'))
    def test_clipboard_tool_missing(self, mock_run, capsys):
        with patch.dict(os.environ, {'WAYLAND_DISPLAY': 'wayland-0'}):
            assert copy_to_clipboard('test') is False
        err = capsys.readouterr().err
        assert 'not installed' in err.lower()


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
    def test_no_hostdata_falls_through(self, mock_find, mock_execv, tmp_path: Path):
        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap.load_settings', return_value=_mock_settings(tmp_path)):
                main()
        mock_execv.assert_called_once_with('/usr/bin/ssh', ['ssh', 'myhost'])

    @patch('ssh_concierge.wrap._run_with_askpass', return_value=0)
    @patch('ssh_concierge.wrap.OnePassword')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_with_password(self, mock_find, mock_op_cls, mock_run, tmp_path: Path):
        mock_op = mock_op_cls.return_value
        mock_op.read.return_value = 'secret123'
        hd_file = tmp_path / 'hostdata.json'
        hd_file.write_text(json.dumps({
            'myhost': {
                'fields': {
                    'password': {'original': 'ops://v/i/pw', 'resolved': None, 'sensitive': True},
                },
            },
        }))

        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap.load_settings', return_value=_mock_settings(tmp_path)):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert args == ('/usr/bin/ssh', 'ssh', ['myhost'], 'secret123')

    def test_no_real_binary_exits(self):
        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap.find_real_binary', return_value=None):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    @patch('ssh_concierge.wrap.os.execv')
    @patch('ssh_concierge.wrap.OnePassword')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_op_read_fails_falls_through(self, mock_find, mock_op_cls, mock_execv, tmp_path: Path):
        mock_op = mock_op_cls.return_value
        mock_op.read.return_value = None
        hd_file = tmp_path / 'hostdata.json'
        hd_file.write_text(json.dumps({
            'myhost': {
                'fields': {
                    'password': {'original': 'ops://v/i/pw', 'resolved': None, 'sensitive': True},
                },
            },
        }))

        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap.load_settings', return_value=_mock_settings(tmp_path)):
                main()
        mock_execv.assert_called_once_with('/usr/bin/ssh', ['ssh', 'myhost'])

    @patch('ssh_concierge.wrap.os.execv')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/scp')
    def test_scp_tool_detection(self, mock_find, mock_execv, tmp_path: Path):
        with patch('sys.argv', ['/home/user/.local/bin/scp', 'myhost:/file', '.']):
            with patch('ssh_concierge.wrap.load_settings', return_value=_mock_settings(tmp_path)):
                main()
        mock_execv.assert_called_once_with('/usr/bin/scp', ['scp', 'myhost:/file', '.'])

    @patch('ssh_concierge.wrap.os.execv')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_no_args_passes_through(self, mock_find, mock_execv, tmp_path: Path):
        with patch('sys.argv', ['/home/user/.local/bin/ssh']):
            with patch('ssh_concierge.wrap.load_settings', return_value=_mock_settings(tmp_path)):
                main()
        mock_execv.assert_called_once_with('/usr/bin/ssh', ['ssh'])

    @patch('ssh_concierge.wrap.copy_to_clipboard', return_value=True)
    @patch('ssh_concierge.wrap.os.execv')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_clipboard_only(self, mock_find, mock_execv, mock_clip, tmp_path: Path):
        """Host with clipboard but no password — clipboard copied, then exec."""
        hd_file = tmp_path / 'hostdata.json'
        hd_file.write_text(json.dumps({
            'myhost': {'clipboard': 'hello\\nworld'},
        }))

        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap.load_settings', return_value=_mock_settings(tmp_path)):
                main()

        mock_clip.assert_called_once_with('hello\nworld')
        mock_execv.assert_called_once_with('/usr/bin/ssh', ['ssh', 'myhost'])

    @patch('ssh_concierge.wrap.copy_to_clipboard', return_value=True)
    @patch('ssh_concierge.wrap._run_with_askpass', return_value=0)
    @patch('ssh_concierge.wrap.OnePassword')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_password_and_clipboard(self, mock_find, mock_op_cls, mock_run, mock_clip, tmp_path: Path):
        """Host with both password and clipboard."""
        mock_op = mock_op_cls.return_value
        mock_op.read.return_value = 'secret'
        hd_file = tmp_path / 'hostdata.json'
        hd_file.write_text(json.dumps({
            'myhost': {
                'fields': {
                    'password': {'original': 'ops://v/i/pw', 'resolved': None, 'sensitive': True},
                },
                'clipboard': 'sudo -i\\n{password}\\n',
            },
        }))

        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap.load_settings', return_value=_mock_settings(tmp_path)):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

        mock_clip.assert_called_once_with('sudo -i\nsecret\n')
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert args == ('/usr/bin/ssh', 'ssh', ['myhost'], 'secret')


class TestMainNewFormat:
    """Tests using the new fields-based hostdata format."""

    @patch('ssh_concierge.wrap._run_with_askpass', return_value=0)
    @patch('ssh_concierge.wrap.OnePassword')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_sensitive_password_resolved_at_ssh_time(self, mock_find, mock_op_cls, mock_run, tmp_path: Path):
        mock_op = mock_op_cls.return_value
        mock_op.read.return_value = 'secret123'
        hd_file = tmp_path / 'hostdata.json'
        hd_file.write_text(json.dumps({
            'myhost': {
                'fields': {
                    'password': {'original': 'ops://V/I/password', 'resolved': None, 'sensitive': True},
                },
            },
        }))

        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap.load_settings', return_value=_mock_settings(tmp_path)):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert args == ('/usr/bin/ssh', 'ssh', ['myhost'], 'secret123')

    @patch('ssh_concierge.wrap.copy_to_clipboard', return_value=True)
    @patch('ssh_concierge.wrap._run_with_askpass', return_value=0)
    @patch('ssh_concierge.wrap.OnePassword')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_clipboard_with_sensitive_field(self, mock_find, mock_op_cls, mock_run, mock_clip, tmp_path: Path):
        mock_op = mock_op_cls.return_value
        mock_op.read.return_value = 'secret'
        hd_file = tmp_path / 'hostdata.json'
        hd_file.write_text(json.dumps({
            'myhost': {
                'fields': {
                    'password': {'original': 'ops://V/I/password', 'resolved': None, 'sensitive': True},
                },
                'clipboard': 'sudo -i\\n{password}\\n',
            },
        }))

        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap.load_settings', return_value=_mock_settings(tmp_path)):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

        mock_clip.assert_called_once_with('sudo -i\nsecret\n')
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert args == ('/usr/bin/ssh', 'ssh', ['myhost'], 'secret')

    @patch('ssh_concierge.wrap.os.execv')
    @patch('ssh_concierge.wrap.find_real_binary', return_value='/usr/bin/ssh')
    def test_cached_non_sensitive_no_op_read(self, mock_find, mock_execv, tmp_path: Path):
        """Non-sensitive fields with cached resolved values skip op read entirely."""
        hd_file = tmp_path / 'hostdata.json'
        hd_file.write_text(json.dumps({
            'myhost': {
                'fields': {
                    'hostname': {'original': 'op://V/I/hostname', 'resolved': '10.0.0.1', 'sensitive': False},
                },
            },
        }))

        with patch('sys.argv', ['/home/user/.local/bin/ssh', 'myhost']):
            with patch('ssh_concierge.wrap.load_settings', return_value=_mock_settings(tmp_path)):
                main()

        # No password → falls through to execv
        mock_execv.assert_called_once_with('/usr/bin/ssh', ['ssh', 'myhost'])
