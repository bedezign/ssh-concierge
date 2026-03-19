"""Configuration file discovery and settings management."""

from __future__ import annotations

import os
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path


_APP_NAME = 'ssh-concierge'
_CONFIG_FILENAME = 'config.toml'


def _find_config_file() -> Path | None:
    """Find the config file in standard locations.

    Search order:
    1. $XDG_CONFIG_HOME/ssh-concierge/config.toml
    2. ~/.config/ssh-concierge/config.toml  (XDG default, if XDG_CONFIG_HOME unset)
    3. ~/.ssh-concierge/config.toml  (non-XDG fallback)
    """
    xdg = os.environ.get('XDG_CONFIG_HOME')
    if xdg:
        candidates = [Path(xdg) / _APP_NAME / _CONFIG_FILENAME]
    else:
        candidates = [Path.home() / '.config' / _APP_NAME / _CONFIG_FILENAME]
    candidates.append(Path.home() / f'.{_APP_NAME}' / _CONFIG_FILENAME)

    for path in candidates:
        if path.is_file():
            return path
    return None


def _default_runtime_dir() -> Path:
    """Return the default runtime directory (XDG_RUNTIME_DIR or /tmp fallback).

    The fallback path is resolved to a physical path so that symlinks
    (e.g. macOS /tmp → /private/tmp) don't cause mismatches between
    the generated Include path and the actual file location.
    """
    xdg = os.environ.get('XDG_RUNTIME_DIR')
    if xdg:
        return Path(xdg) / _APP_NAME
    return (Path(tempfile.gettempdir()) / f'{_APP_NAME}-{os.getuid()}').resolve()


@dataclass(frozen=True)
class Settings:
    """Resolved configuration with all defaults applied."""

    runtime_dir: Path
    askpass_dir: Path
    ttl: int
    op_timeout: int
    config_file: Path | None  # Path to the config file that was loaded (None = defaults)
    key_mode: int = 0o600
    askpass_password: tuple[str, ...] = ('*assword*',)
    askpass_otp: tuple[str, ...] = ()

    @property
    def hosts_file(self) -> Path:
        return self.runtime_dir / 'hosts.conf'

    @property
    def hostdata_file(self) -> Path:
        return self.runtime_dir / 'hostdata.json'

    @property
    def keys_dir(self) -> Path:
        return self.runtime_dir / 'keys'

    @property
    def env_file(self) -> Path:
        return self.runtime_dir / 'env.sh'

    @property
    def lock_file(self) -> Path:
        return self.runtime_dir / '.lock'

    @property
    def askpass_file(self) -> Path:
        return self.askpass_dir / 'askpass'

    def key_file(self, fingerprint: str) -> Path:
        """Path to a public key file for the given fingerprint."""
        return self.keys_dir / f'{fingerprint.replace("/", "_")}.pub'

    def get(self, directive: str) -> str:
        """Get a directive value as a string for CLI output."""
        match directive:
            case 'runtime_dir':
                return str(self.runtime_dir)
            case 'askpass_dir':
                return str(self.askpass_dir)
            case 'ttl':
                return str(self.ttl)
            case 'op_timeout':
                return str(self.op_timeout)
            case 'hosts_file':
                return str(self.hosts_file)
            case 'hostdata_file':
                return str(self.hostdata_file)
            case 'keys_dir':
                return str(self.keys_dir)
            case 'env_file':
                return str(self.env_file)
            case 'lock_file':
                return str(self.lock_file)
            case 'askpass_file':
                return str(self.askpass_file)
            case 'config_file':
                return str(self.config_file) if self.config_file else ''
            case 'key_mode':
                return format(self.key_mode, '#o')
            case 'askpass_password':
                return ', '.join(self.askpass_password)
            case 'askpass_otp':
                return ', '.join(self.askpass_otp)
            case _:
                raise KeyError(f'unknown directive: {directive}')

    DIRECTIVES = (
        'config_file',
        'runtime_dir',
        'askpass_dir',
        'hosts_file',
        'hostdata_file',
        'keys_dir',
        'env_file',
        'lock_file',
        'askpass_file',
        'ttl',
        'op_timeout',
        'key_mode',
        'askpass_password',
        'askpass_otp',
    )


# Directives that users can set in the config file
_CONFIGURABLE = {'runtime_dir', 'askpass_dir', 'ttl', 'op_timeout', 'key_mode', 'askpass'}

_DEFAULTS = {
    'ttl': 3600,
    'op_timeout': 120,
}


def load_settings() -> Settings:
    """Load settings from config file with defaults.

    Config file is optional — all values have sensible defaults.
    """
    config_file = _find_config_file()
    raw: dict = {}

    if config_file:
        try:
            raw = tomllib.loads(config_file.read_text())
        except (OSError, tomllib.TOMLDecodeError) as exc:
            print(
                f'ssh-concierge: error reading {config_file}: {exc}',
                file=sys.stderr,
            )
            # Fall through with defaults

    unknown = set(raw) - _CONFIGURABLE
    if unknown:
        print(
            f'ssh-concierge: unknown config directives: {", ".join(sorted(unknown))}',
            file=sys.stderr,
        )

    runtime_dir = Path(raw['runtime_dir']).resolve() if 'runtime_dir' in raw else _default_runtime_dir()
    askpass_dir = Path(raw['askpass_dir']) if 'askpass_dir' in raw else runtime_dir
    ttl = int(raw.get('ttl', _DEFAULTS['ttl']))
    op_timeout = int(raw.get('op_timeout', _DEFAULTS['op_timeout']))
    key_mode = int(raw.get('key_mode', 0o600))

    askpass_section = raw.get('askpass', {})
    askpass_password = tuple(askpass_section.get('password', ['*assword*']))
    askpass_otp = tuple(askpass_section.get('otp', []))

    return Settings(
        runtime_dir=runtime_dir,
        askpass_dir=askpass_dir,
        ttl=ttl,
        op_timeout=op_timeout,
        config_file=config_file,
        key_mode=key_mode,
        askpass_password=askpass_password,
        askpass_otp=askpass_otp,
    )
