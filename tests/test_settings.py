"""Tests for ssh_concierge.settings."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from ssh_concierge.settings import Settings, _default_runtime_dir, _find_config_file, load_settings


class TestFindConfigFile:
    def test_xdg_config_home(self, tmp_path: Path):
        config_dir = tmp_path / 'ssh-concierge'
        config_dir.mkdir()
        config_file = config_dir / 'config.toml'
        config_file.write_text('ttl = 1800')

        with patch.dict(os.environ, {'XDG_CONFIG_HOME': str(tmp_path)}):
            result = _find_config_file()
        assert result == config_file

    def test_default_xdg_path(self, tmp_path: Path):
        config_dir = tmp_path / '.config' / 'ssh-concierge'
        config_dir.mkdir(parents=True)
        config_file = config_dir / 'config.toml'
        config_file.write_text('ttl = 1800')

        with patch.dict(os.environ, {}, clear=True):
            with patch('ssh_concierge.settings.Path.home', return_value=tmp_path):
                result = _find_config_file()
        assert result == config_file

    def test_fallback_dot_ssh_concierge(self, tmp_path: Path):
        config_dir = tmp_path / '.ssh-concierge'
        config_dir.mkdir()
        config_file = config_dir / 'config.toml'
        config_file.write_text('ttl = 1800')

        with patch.dict(os.environ, {}, clear=True):
            with patch('ssh_concierge.settings.Path.home', return_value=tmp_path):
                result = _find_config_file()
        assert result == config_file

    def test_xdg_takes_precedence_over_fallback(self, tmp_path: Path):
        xdg_dir = tmp_path / '.config' / 'ssh-concierge'
        xdg_dir.mkdir(parents=True)
        xdg_file = xdg_dir / 'config.toml'
        xdg_file.write_text('ttl = 1')

        fallback_dir = tmp_path / '.ssh-concierge'
        fallback_dir.mkdir()
        (fallback_dir / 'config.toml').write_text('ttl = 2')

        with patch.dict(os.environ, {}, clear=True):
            with patch('ssh_concierge.settings.Path.home', return_value=tmp_path):
                result = _find_config_file()
        assert result == xdg_file

    def test_no_config_file(self, tmp_path: Path):
        with patch.dict(os.environ, {}, clear=True):
            with patch('ssh_concierge.settings.Path.home', return_value=tmp_path):
                result = _find_config_file()
        assert result is None


class TestLoadSettings:
    def test_defaults_no_config_file(self, tmp_path: Path):
        with patch('ssh_concierge.settings._find_config_file', return_value=None):
            with patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(tmp_path / 'run')}):
                settings = load_settings()

        assert settings.runtime_dir == tmp_path / 'run' / 'ssh-concierge'
        assert settings.askpass_dir == settings.runtime_dir
        assert settings.ttl == 0
        assert settings.op_timeout == 120
        assert settings.key_mode == 0o600
        assert settings.config_file is None

    def test_overrides_from_config(self, tmp_path: Path):
        config_file = tmp_path / 'config.toml'
        config_file.write_text(
            'runtime_dir = "/custom/runtime"\n'
            'askpass_dir = "/custom/askpass"\n'
            'ttl = 7200\n'
            'op_timeout = 60\n'
        )

        with patch('ssh_concierge.settings._find_config_file', return_value=config_file):
            settings = load_settings()

        assert settings.runtime_dir == Path('/custom/runtime').resolve()
        assert settings.askpass_dir == Path('/custom/askpass')
        assert settings.ttl == 7200
        assert settings.op_timeout == 60
        assert settings.config_file == config_file

    def test_askpass_defaults_to_runtime_dir(self, tmp_path: Path):
        config_file = tmp_path / 'config.toml'
        config_file.write_text('runtime_dir = "/custom/runtime"\n')

        with patch('ssh_concierge.settings._find_config_file', return_value=config_file):
            settings = load_settings()

        assert settings.askpass_dir == Path('/custom/runtime').resolve()

    def test_unknown_directives_warned(self, tmp_path: Path, capsys):
        config_file = tmp_path / 'config.toml'
        config_file.write_text('bogus = "value"\n')

        with patch('ssh_concierge.settings._find_config_file', return_value=config_file):
            load_settings()

        err = capsys.readouterr().err
        assert 'unknown' in err.lower()
        assert 'bogus' in err

    def test_malformed_toml_falls_back(self, tmp_path: Path, capsys):
        config_file = tmp_path / 'config.toml'
        config_file.write_text('not valid toml [[[')

        with patch('ssh_concierge.settings._find_config_file', return_value=config_file):
            settings = load_settings()

        assert settings.ttl == 0  # defaults
        err = capsys.readouterr().err
        assert 'error reading' in err.lower()

    def test_runtime_dir_fallback_without_xdg(self):
        with patch('ssh_concierge.settings._find_config_file', return_value=None):
            with patch.dict(os.environ, {}, clear=True):
                with patch('os.getuid', return_value=1000):
                    settings = load_settings()

        # Path is resolved, so compare resolved form
        assert settings.runtime_dir == Path('/tmp/ssh-concierge-1000').resolve()

    def test_askpass_defaults_when_no_section(self, tmp_path: Path):
        with patch('ssh_concierge.settings._find_config_file', return_value=None):
            with patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(tmp_path / 'run')}):
                settings = load_settings()

        assert settings.askpass_password == ('*assword*',)
        assert settings.askpass_otp == ()
        assert settings.key_mode == 0o600

    def test_key_mode_from_config(self, tmp_path: Path):
        config_file = tmp_path / 'config.toml'
        config_file.write_text('key_mode = 0o644\n')

        with patch('ssh_concierge.settings._find_config_file', return_value=config_file):
            settings = load_settings()

        assert settings.key_mode == 0o644

    def test_askpass_from_config(self, tmp_path: Path):
        config_file = tmp_path / 'config.toml'
        config_file.write_text(
            '[askpass]\n'
            'password = ["*assword*", "*ASSWORD*"]\n'
            'otp = ["*erification*code*", "*one-time*"]\n'
        )

        with patch('ssh_concierge.settings._find_config_file', return_value=config_file):
            settings = load_settings()

        assert settings.askpass_password == ('*assword*', '*ASSWORD*')
        assert settings.askpass_otp == ('*erification*code*', '*one-time*')

    def test_askpass_empty_password_list(self, tmp_path: Path):
        config_file = tmp_path / 'config.toml'
        config_file.write_text(
            '[askpass]\n'
            'password = []\n'
        )

        with patch('ssh_concierge.settings._find_config_file', return_value=config_file):
            settings = load_settings()

        assert settings.askpass_password == ()
        assert settings.askpass_otp == ()

    def test_askpass_section_not_flagged_as_unknown(self, tmp_path: Path, capsys):
        config_file = tmp_path / 'config.toml'
        config_file.write_text(
            '[askpass]\n'
            'password = ["*assword*"]\n'
        )

        with patch('ssh_concierge.settings._find_config_file', return_value=config_file):
            load_settings()

        err = capsys.readouterr().err
        assert 'unknown' not in err.lower()


class TestDefaultRuntimeDir:
    def test_returns_resolved_path(self):
        """Ensure _default_runtime_dir() returns a resolved path (no symlink components)."""
        with patch.dict(os.environ, {}, clear=True):
            with patch('os.getuid', return_value=1000):
                result = _default_runtime_dir()
        assert result == result.resolve()

    def test_xdg_runtime_dir_used_when_set(self, tmp_path: Path):
        with patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(tmp_path)}):
            result = _default_runtime_dir()
        assert result == tmp_path / 'ssh-concierge'


class TestSettingsGet:
    def _settings(self, tmp_path: Path) -> Settings:
        return Settings(
            runtime_dir=tmp_path / 'runtime',
            askpass_dir=tmp_path / 'askpass',
            ttl=1800,
            op_timeout=60,
            config_file=tmp_path / 'config.toml',
        )

    def test_get_runtime_dir(self, tmp_path: Path):
        assert self._settings(tmp_path).get('runtime_dir') == str(tmp_path / 'runtime')

    def test_get_hosts_file(self, tmp_path: Path):
        assert self._settings(tmp_path).get('hosts_file') == str(tmp_path / 'runtime' / 'hosts.conf')

    def test_get_ttl(self, tmp_path: Path):
        assert self._settings(tmp_path).get('ttl') == '1800'

    def test_get_config_file(self, tmp_path: Path):
        assert self._settings(tmp_path).get('config_file') == str(tmp_path / 'config.toml')

    def test_get_config_file_none(self, tmp_path: Path):
        s = Settings(
            runtime_dir=tmp_path, askpass_dir=tmp_path,
            ttl=3600, op_timeout=120, config_file=None,
        )
        assert s.get('config_file') == ''

    def test_get_key_mode(self, tmp_path: Path):
        assert self._settings(tmp_path).get('key_mode') == '0o600'

    def test_get_key_mode_custom(self, tmp_path: Path):
        s = Settings(
            runtime_dir=tmp_path, askpass_dir=tmp_path,
            ttl=3600, op_timeout=120, config_file=None,
            key_mode=0o644,
        )
        assert s.get('key_mode') == '0o644'

    def test_get_askpass_password(self, tmp_path: Path):
        assert self._settings(tmp_path).get('askpass_password') == '*assword*'

    def test_get_askpass_otp_empty(self, tmp_path: Path):
        assert self._settings(tmp_path).get('askpass_otp') == ''

    def test_get_unknown_raises(self, tmp_path: Path):
        with pytest.raises(KeyError):
            self._settings(tmp_path).get('nonexistent')

    def test_get_env_file(self, tmp_path: Path):
        assert self._settings(tmp_path).get('env_file') == str(tmp_path / 'runtime' / 'env.sh')

    def test_get_lock_file(self, tmp_path: Path):
        assert self._settings(tmp_path).get('lock_file') == str(tmp_path / 'runtime' / '.lock')

    def test_get_askpass_file(self, tmp_path: Path):
        assert self._settings(tmp_path).get('askpass_file') == str(tmp_path / 'askpass' / 'askpass')

    def test_all_directives_accessible(self, tmp_path: Path):
        s = self._settings(tmp_path)
        for d in Settings.DIRECTIVES:
            s.get(d)  # should not raise


class TestKeyFile:
    def test_basic_fingerprint(self, tmp_path: Path):
        s = Settings(
            runtime_dir=tmp_path, askpass_dir=tmp_path,
            ttl=3600, op_timeout=120, config_file=None,
        )
        assert s.key_file('SHA256:abc123') == tmp_path / 'keys' / 'SHA256:abc123.pub'

    def test_fingerprint_with_slashes(self, tmp_path: Path):
        s = Settings(
            runtime_dir=tmp_path, askpass_dir=tmp_path,
            ttl=3600, op_timeout=120, config_file=None,
        )
        fp = 'SHA256:HTjIA6pyekTD2wxmf0qyUZla8nAz/tpEcF0v3/nsa/.w'
        expected = tmp_path / 'keys' / 'SHA256:HTjIA6pyekTD2wxmf0qyUZla8nAz_tpEcF0v3_nsa_.w.pub'
        assert s.key_file(fp) == expected
