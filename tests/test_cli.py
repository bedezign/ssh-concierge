"""Tests for ssh_concierge.cli."""

import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from tests.conftest import fv

import pytest

from ssh_concierge.cli import (
    cmd_generate, cmd_flush, cmd_status, cmd_list, cmd_debug, main,
    _parse_op_item_ref, _build_key_registry, _resolve_key_ref,
    _load_cached_hostdata, _warn_noexec_askpass, resolve_host_fields,
)
from ssh_concierge.deploy import cmd_deploy_key
from ssh_concierge.field import FieldValue
from ssh_concierge.models import HostConfig
from ssh_concierge.onepassword import OpError
from ssh_concierge.password import ItemMeta
from ssh_concierge.settings import Settings


def _make_settings(runtime_dir: Path) -> Settings:
    """Create a Settings pointing at a test runtime directory."""
    return Settings(
        runtime_dir=runtime_dir,
        askpass_dir=runtime_dir,
        ttl=3600,
        op_timeout=120,
        config_file=None,
    )


@pytest.fixture()
def runtime_dir(tmp_path: Path) -> Path:
    """Provide a temporary runtime directory."""
    return tmp_path / "ssh-concierge"


@pytest.fixture()
def settings(runtime_dir: Path) -> Settings:
    """Provide Settings pointing at a temporary runtime directory."""
    return _make_settings(runtime_dir)


SAMPLE_HOSTS = [
    HostConfig(
        aliases=["prod", "prod-web"],
        hostname=fv("10.0.0.1", "hostname"),
        port=fv("22", "port"),
        user=fv("deploy", "user"),
        public_key="ssh-ed25519 AAAAprod prod-key",
        fingerprint="SHA256:prodkey",
    ),
    HostConfig(
        aliases=["bastion"],
        hostname=fv("10.0.0.254", "hostname"),
        public_key="ssh-rsa AAAAbastion bastion-key",
        fingerprint="SHA256:bastionkey",
    ),
]


class TestCmdGenerate:
    @patch("ssh_concierge.cli.OnePassword")
    def test_generates_config(self, mock_op_cls, runtime_dir: Path):
        mock_op = mock_op_cls.return_value
        mock_op.list_managed_item_ids.return_value = ["id1", "id2"]
        mock_op.get_item.side_effect = [
            {"id": "id1", "vault": {"id": "v1"}, "fields": []},
            {"id": "id2", "vault": {"id": "v2"}, "fields": []},
        ]

        with patch("ssh_concierge.cli.parse_item_to_host_configs") as mock_parse:
            mock_parse.side_effect = [[SAMPLE_HOSTS[0]], [SAMPLE_HOSTS[1]]]
            cmd_generate(_make_settings(runtime_dir))

        conf = runtime_dir / "hosts.conf"
        assert conf.exists()
        content = conf.read_text()
        assert "Host prod prod-web" in content
        assert "Host bastion" in content

    @patch("ssh_concierge.cli.OnePassword")
    def test_skips_unparseable_items(self, mock_op_cls, runtime_dir: Path):
        mock_op = mock_op_cls.return_value
        mock_op.list_managed_item_ids.return_value = ["id1"]
        mock_op.get_item.return_value = {"id": "id1", "vault": {"id": "v1"}, "fields": []}

        with patch("ssh_concierge.cli.parse_item_to_host_configs") as mock_parse:
            mock_parse.return_value = []
            cmd_generate(_make_settings(runtime_dir))

        conf = runtime_dir / "hosts.conf"
        assert conf.exists()
        # Only header, no Host blocks
        assert "Host " not in conf.read_text()

    @patch("ssh_concierge.cli.OnePassword")
    def test_op_error_raises(self, mock_op_cls, runtime_dir: Path):
        mock_op = mock_op_cls.return_value
        mock_op.list_managed_item_ids.side_effect = OpError("not signed in")
        with pytest.raises(OpError):
            cmd_generate(_make_settings(runtime_dir))

    @patch("ssh_concierge.cli.socket")
    @patch("ssh_concierge.cli.OnePassword")
    def test_host_filter_includes_matching(self, mock_op_cls, mock_socket, runtime_dir: Path):
        mock_socket.gethostname.return_value = "alpha"
        mock_op = mock_op_cls.return_value
        mock_op.list_managed_item_ids.return_value = ["id1"]
        mock_op.get_item.return_value = {"id": "id1", "vault": {"id": "v1"}, "fields": []}

        matching_host = HostConfig(
            aliases=["work-server"],
            hostname=fv("10.0.0.1", "hostname"),
            host_filter="alpha",
        )
        with patch("ssh_concierge.cli.parse_item_to_host_configs") as mock_parse:
            mock_parse.return_value = [matching_host]
            cmd_generate(_make_settings(runtime_dir))

        content = (runtime_dir / "hosts.conf").read_text()
        assert "Host work-server" in content

    @patch("ssh_concierge.cli.socket")
    @patch("ssh_concierge.cli.OnePassword")
    def test_host_filter_excludes_non_matching(self, mock_op_cls, mock_socket, runtime_dir: Path):
        mock_socket.gethostname.return_value = "beta"
        mock_op = mock_op_cls.return_value
        mock_op.list_managed_item_ids.return_value = ["id1"]
        mock_op.get_item.return_value = {"id": "id1", "vault": {"id": "v1"}, "fields": []}

        filtered_host = HostConfig(
            aliases=["work-server"],
            hostname=fv("10.0.0.1", "hostname"),
            host_filter="alpha",
        )
        with patch("ssh_concierge.cli.parse_item_to_host_configs") as mock_parse:
            mock_parse.return_value = [filtered_host]
            cmd_generate(_make_settings(runtime_dir))

        content = (runtime_dir / "hosts.conf").read_text()
        assert "Host work-server" not in content


class TestCmdFlush:
    def test_removes_runtime_dir(self, runtime_dir: Path):
        runtime_dir.mkdir(parents=True)
        (runtime_dir / "hosts.conf").write_text("test")
        keys_dir = runtime_dir / "keys"
        keys_dir.mkdir()
        (keys_dir / "key.pub").write_text("key")

        cmd_flush(_make_settings(runtime_dir))

        assert not runtime_dir.exists()

    def test_flush_nonexistent_is_noop(self, runtime_dir: Path):
        cmd_flush(_make_settings(runtime_dir))  # should not raise


class TestCmdStatus:
    def test_no_config(self, runtime_dir: Path, capsys):
        cmd_status(_make_settings(runtime_dir))
        output = capsys.readouterr().out
        assert "not generated" in output.lower() or "no config" in output.lower()

    def test_with_config(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        conf = runtime_dir / "hosts.conf"
        conf.write_text("# Generated by ssh-concierge\n\nHost prod\n    HostName 10.0.0.1\n")

        cmd_status(_make_settings(runtime_dir))
        output = capsys.readouterr().out
        assert "1" in output  # 1 host


class TestCmdList:
    def test_list_hosts(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        conf = runtime_dir / "hosts.conf"
        conf.write_text(
            "# Generated by ssh-concierge\n\n"
            "Host prod prod-web\n    HostName 10.0.0.1\n\n"
            "Host bastion\n    HostName 10.0.0.254\n"
        )

        cmd_list(_make_settings(runtime_dir))
        output = capsys.readouterr().out
        assert "prod" in output
        assert "bastion" in output

    def test_list_no_config(self, runtime_dir: Path, capsys):
        cmd_list(_make_settings(runtime_dir))
        output = capsys.readouterr().out
        assert "not generated" in output.lower() or "no config" in output.lower()


SAMPLE_HOSTS_CONF = (
    "# Generated by ssh-concierge\n\n"
    "Host prod prod-web-01\n"
    "    HostName 203.0.113.42\n"
    "    Port 2222\n"
    "    User deploy\n"
    "    IdentityFile /run/user/1000/ssh-concierge/keys/SHA256:abc123.pub\n"
    "    ProxyJump bastion\n\n"
    "Host bastion\n"
    "    HostName 10.0.0.254\n"
    "    IdentityFile /run/user/1000/ssh-concierge/keys/SHA256:bastionkey.pub\n"
)

SAMPLE_HOSTDATA = {
    "prod": {
        "fields": {
            "password": {"original": "op://Work/ServerLogin/password", "resolved": None, "sensitive": True},
        },
    },
    "prod-web-01": {
        "fields": {
            "password": {"original": "op://Work/ServerLogin/password", "resolved": None, "sensitive": True},
        },
    },
}


class TestCmdDebug:
    def test_alias_found_outputs_host_block(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        (runtime_dir / "hosts.conf").write_text(SAMPLE_HOSTS_CONF)

        cmd_debug("prod", _make_settings(runtime_dir))
        output = capsys.readouterr().out

        assert "Host prod prod-web-01" in output
        assert "HostName 203.0.113.42" in output
        assert "Port 2222" in output
        assert "User deploy" in output
        assert "ProxyJump bastion" in output

    def test_alias_not_found(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        (runtime_dir / "hosts.conf").write_text(SAMPLE_HOSTS_CONF)

        cmd_debug("nonexistent", _make_settings(runtime_dir))
        output = capsys.readouterr().out

        assert "not found" in output.lower()

    def test_no_config(self, runtime_dir: Path, capsys):
        cmd_debug("prod", _make_settings(runtime_dir))
        output = capsys.readouterr().out

        assert "no config" in output.lower()

    def test_alias_with_password_reference(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        (runtime_dir / "hosts.conf").write_text(SAMPLE_HOSTS_CONF)
        (runtime_dir / "hostdata.json").write_text(json.dumps(SAMPLE_HOSTDATA))

        cmd_debug("prod", _make_settings(runtime_dir))
        output = capsys.readouterr().out

        assert "op://Work/ServerLogin/password" in output

    def test_alias_without_password(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        (runtime_dir / "hosts.conf").write_text(SAMPLE_HOSTS_CONF)

        cmd_debug("bastion", _make_settings(runtime_dir))
        output = capsys.readouterr().out

        assert "Host bastion" in output
        assert "Password" not in output

    def test_multi_alias_matches_any(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        (runtime_dir / "hosts.conf").write_text(SAMPLE_HOSTS_CONF)

        cmd_debug("prod-web-01", _make_settings(runtime_dir))
        output = capsys.readouterr().out

        assert "Host prod prod-web-01" in output
        assert "HostName 203.0.113.42" in output

    def test_alias_with_clipboard(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        (runtime_dir / "hosts.conf").write_text(SAMPLE_HOSTS_CONF)
        hd = {
            "prod": {
                "fields": {
                    "password": {"original": "op://Work/ServerLogin/password", "resolved": None, "sensitive": True},
                },
                "clipboard": "sudo -i\\n{password}\\n",
            },
        }
        (runtime_dir / "hostdata.json").write_text(json.dumps(hd))

        cmd_debug("prod", _make_settings(runtime_dir))
        output = capsys.readouterr().out

        assert "password:" in output
        assert "sensitive, resolved at SSH time" in output
        assert "Clipboard:" in output

    def test_config_age_shown(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        (runtime_dir / "hosts.conf").write_text(SAMPLE_HOSTS_CONF)

        cmd_debug("prod", _make_settings(runtime_dir))
        output = capsys.readouterr().out

        assert "config age" in output.lower()


class TestMain:
    @patch("ssh_concierge.cli.cmd_generate")
    def test_generate_flag(self, mock_gen):
        with patch("sys.argv", ["ssh-concierge", "--generate"]):
            main()
        mock_gen.assert_called_once()

    @patch("ssh_concierge.cli.cmd_flush")
    def test_flush_flag(self, mock_flush):
        with patch("sys.argv", ["ssh-concierge", "--flush"]):
            main()
        mock_flush.assert_called_once()

    @patch("ssh_concierge.cli.cmd_status")
    def test_status_flag(self, mock_status):
        with patch("sys.argv", ["ssh-concierge", "--status"]):
            main()
        mock_status.assert_called_once()

    @patch("ssh_concierge.cli.cmd_list")
    def test_list_flag(self, mock_list):
        with patch("sys.argv", ["ssh-concierge", "--list"]):
            main()
        mock_list.assert_called_once()

    @patch("ssh_concierge.cli.cmd_debug")
    def test_debug_flag(self, mock_debug):
        with patch("sys.argv", ["ssh-concierge", "--debug", "prod"]):
            main()
        mock_debug.assert_called_once()
        assert mock_debug.call_args[0][0] == "prod"

    @patch("ssh_concierge.cli.cmd_deploy_key")
    def test_deploy_key_flag(self, mock_deploy):
        with patch("sys.argv", ["ssh-concierge", "--deploy-key", "worker1"]):
            main()
        mock_deploy.assert_called_once()
        args = mock_deploy.call_args
        assert args[0][0] == "worker1"
        assert args[0][1] is False  # --all not set

    @patch("ssh_concierge.cli.cmd_deploy_key")
    def test_deploy_key_with_all(self, mock_deploy):
        with patch("sys.argv", ["ssh-concierge", "--deploy-key", "worker1", "--all"]):
            main()
        mock_deploy.assert_called_once()
        args = mock_deploy.call_args
        assert args[0][0] == "worker1"
        assert args[0][1] is True  # --all set

    def test_all_without_deploy_key_fails(self):
        with patch("sys.argv", ["ssh-concierge", "--list", "--all"]):
            with pytest.raises(SystemExit):
                main()

    @patch("ssh_concierge.cli.cmd_generate")
    def test_no_cache_flag(self, mock_gen):
        with patch("sys.argv", ["ssh-concierge", "--generate", "--no-cache"]):
            main()
        mock_gen.assert_called_once()
        kwargs = mock_gen.call_args[1]
        assert kwargs['no_cache'] is True

    def test_no_cache_without_generate_fails(self):
        with patch("sys.argv", ["ssh-concierge", "--list", "--no-cache"]):
            with pytest.raises(SystemExit):
                main()


class TestLoadCachedHostdata:
    def test_no_file(self, runtime_dir: Path):
        assert _load_cached_hostdata(runtime_dir) == {}

    def test_empty_file(self, runtime_dir: Path):
        runtime_dir.mkdir(parents=True)
        (runtime_dir / 'hostdata.json').write_text('{}')
        assert _load_cached_hostdata(runtime_dir) == {}

    def test_loads_fields(self, runtime_dir: Path):
        runtime_dir.mkdir(parents=True)
        hd = {
            'myhost': {
                'fields': {
                    'hostname': {'original': 'op://V/I/hostname', 'resolved': '10.0.0.1', 'sensitive': False},
                    'password': {'original': 'ops://V/I/pw', 'resolved': None, 'sensitive': True},
                },
            },
        }
        (runtime_dir / 'hostdata.json').write_text(json.dumps(hd))
        result = _load_cached_hostdata(runtime_dir)
        assert 'myhost' in result
        assert result['myhost']['hostname'].original == 'op://V/I/hostname'
        assert result['myhost']['hostname'].resolved == '10.0.0.1'
        assert result['myhost']['password'].sensitive is True

    def test_skips_entries_without_fields(self, runtime_dir: Path):
        runtime_dir.mkdir(parents=True)
        hd = {
            'myhost': {'clipboard': 'hello'},
        }
        (runtime_dir / 'hostdata.json').write_text(json.dumps(hd))
        result = _load_cached_hostdata(runtime_dir)
        assert 'myhost' not in result

    def test_bad_json(self, runtime_dir: Path):
        runtime_dir.mkdir(parents=True)
        (runtime_dir / 'hostdata.json').write_text('not json')
        assert _load_cached_hostdata(runtime_dir) == {}


class TestParseOpItemRef:
    def test_valid_reference(self):
        assert _parse_op_item_ref('op://Work/MyKey') == ('Work', 'MyKey')

    def test_vault_with_spaces(self):
        assert _parse_op_item_ref('op://My Vault/Key Name') == ('My Vault', 'Key Name')

    def test_no_prefix_still_parses(self):
        """Without op:// prefix the string is split as-is."""
        assert _parse_op_item_ref('Work/MyKey') == ('Work', 'MyKey')

    def test_quoted_item_with_slashes(self):
        assert _parse_op_item_ref('op://Work/"Laptop / SN-001234 / john.doe"') == ('Work', 'Laptop / SN-001234 / john.doe')

    def test_url_encoded_item(self):
        assert _parse_op_item_ref('op://Work/Laptop %2F SN-001234 %2F john.doe') == ('Work', 'Laptop / SN-001234 / john.doe')

    def test_no_prefix_quoted(self):
        assert _parse_op_item_ref('Work/"Laptop / SN-001234"') == ('Work', 'Laptop / SN-001234')

    def test_invalid_no_slash(self):
        with pytest.raises(ValueError):
            _parse_op_item_ref('op://WorkMyKey')

    def test_invalid_empty_vault(self):
        with pytest.raises(ValueError):
            _parse_op_item_ref('op:///MyKey')

    def test_invalid_empty_title(self):
        with pytest.raises(ValueError):
            _parse_op_item_ref('op://Work/')


class TestBuildKeyRegistry:
    def test_builds_from_items(self):
        items = [
            {
                'id': 'key1',
                'title': 'My SSH Key',
                'vault': {'id': 'v1', 'name': 'Work'},
                'fields': [
                    {'label': 'public key', 'value': 'ssh-ed25519 AAAA'},
                    {'label': 'fingerprint', 'value': 'SHA256:abc'},
                ],
            },
        ]
        registry = _build_key_registry(items)
        assert ('work', 'my ssh key') in registry
        assert registry[('work', 'my ssh key')] == ('ssh-ed25519 AAAA', 'SHA256:abc')
        assert ('key1',) in registry

    def test_skips_items_without_key_data(self):
        items = [
            {
                'id': 'nokey',
                'title': 'Server',
                'vault': {'id': 'v1', 'name': 'Work'},
                'fields': [],
            },
        ]
        registry = _build_key_registry(items)
        assert len(registry) == 0

    def test_skips_section_fields(self):
        """Only item-level (no section) public_key/fingerprint are used."""
        items = [
            {
                'id': 'key1',
                'title': 'Key',
                'vault': {'id': 'v1', 'name': 'Work'},
                'fields': [
                    {'label': 'public key', 'value': 'ssh-ed25519 AAAA',
                     'section': {'id': 's', 'label': 'SSH Config'}},
                    {'label': 'fingerprint', 'value': 'SHA256:abc',
                     'section': {'id': 's', 'label': 'SSH Config'}},
                ],
            },
        ]
        registry = _build_key_registry(items)
        assert len(registry) == 0

    def test_multiple_items(self):
        items = [
            {
                'id': 'k1', 'title': 'Key A', 'vault': {'id': 'v1', 'name': 'Work'},
                'fields': [
                    {'label': 'public key', 'value': 'ssh-ed25519 AAAA-A'},
                    {'label': 'fingerprint', 'value': 'SHA256:aaa'},
                ],
            },
            {
                'id': 'k2', 'title': 'Key B', 'vault': {'id': 'v2', 'name': 'Personal'},
                'fields': [
                    {'label': 'public key', 'value': 'ssh-rsa AAAA-B'},
                    {'label': 'fingerprint', 'value': 'SHA256:bbb'},
                ],
            },
        ]
        registry = _build_key_registry(items)
        assert registry[('work', 'key a')] == ('ssh-ed25519 AAAA-A', 'SHA256:aaa')
        assert registry[('personal', 'key b')] == ('ssh-rsa AAAA-B', 'SHA256:bbb')


class TestResolveKeyRef:
    def _registry(self):
        return {
            ('work', 'my ssh key'): ('ssh-ed25519 AAAA', 'SHA256:abc'),
            ('k1',): ('ssh-ed25519 AAAA', 'SHA256:abc'),
        }

    def test_resolves_key_ref(self):
        host = HostConfig(
            aliases=['myhost'],
            hostname=fv('10.0.0.1', 'hostname'),
            key_ref='op://Work/My SSH Key',
        )
        result = _resolve_key_ref(host, self._registry())
        assert result.public_key == 'ssh-ed25519 AAAA'
        assert result.fingerprint == 'SHA256:abc'
        assert result.key_ref == 'op://Work/My SSH Key'  # preserved

    def test_already_has_public_key(self):
        """key_ref is ignored when host already has a public_key."""
        host = HostConfig(
            aliases=['myhost'],
            hostname=fv('10.0.0.1', 'hostname'),
            public_key='ssh-rsa existing',
            fingerprint='SHA256:existing',
            key_ref='op://Work/My SSH Key',
        )
        result = _resolve_key_ref(host, self._registry())
        assert result.public_key == 'ssh-rsa existing'
        assert result.fingerprint == 'SHA256:existing'

    def test_no_key_ref(self):
        host = HostConfig(aliases=['myhost'], hostname=fv('10.0.0.1', 'hostname'))
        result = _resolve_key_ref(host, self._registry())
        assert result is host  # unchanged

    def test_key_not_found(self, capsys):
        host = HostConfig(
            aliases=['myhost'],
            hostname=fv('10.0.0.1', 'hostname'),
            key_ref='op://Work/Nonexistent',
        )
        result = _resolve_key_ref(host, self._registry())
        assert result.public_key is None
        assert result.fingerprint is None
        err = capsys.readouterr().err
        assert 'not found' in err
        assert 'myhost' in err

    def test_invalid_ref(self, capsys):
        host = HostConfig(
            aliases=['myhost'],
            hostname=fv('10.0.0.1', 'hostname'),
            key_ref='not-a-valid-ref',
        )
        result = _resolve_key_ref(host, self._registry())
        assert result.public_key is None
        err = capsys.readouterr().err
        assert 'invalid key reference' in err
        assert 'myhost' in err

    def test_case_insensitive_lookup(self):
        host = HostConfig(
            aliases=['myhost'],
            hostname=fv('10.0.0.1', 'hostname'),
            key_ref='op://WORK/MY SSH KEY',
        )
        result = _resolve_key_ref(host, self._registry())
        assert result.public_key == 'ssh-ed25519 AAAA'

    def test_url_encoded_slashes_in_item_name(self):
        registry = {
            ('work', 'laptop / sn-001234 / john.doe'): ('ssh-ed25519 BBBB', 'SHA256:xyz'),
        }
        host = HostConfig(
            aliases=['work-laptop'],
            hostname=fv('192.168.30.200', 'hostname'),
            key_ref='op://Work/Laptop %2F SN-001234 %2F john.doe',
        )
        result = _resolve_key_ref(host, registry)
        assert result.public_key == 'ssh-ed25519 BBBB'
        assert result.fingerprint == 'SHA256:xyz'

    def test_quoted_slashes_in_item_name(self):
        registry = {
            ('work', 'laptop / sn-001234'): ('ssh-ed25519 CCCC', 'SHA256:qrs'),
        }
        host = HostConfig(
            aliases=['work-laptop'],
            hostname=fv('192.168.30.200', 'hostname'),
            key_ref='op://Work/"Laptop / SN-001234"',
        )
        result = _resolve_key_ref(host, registry)
        assert result.public_key == 'ssh-ed25519 CCCC'
        assert result.fingerprint == 'SHA256:qrs'

    def test_self_ref_resolved_via_seeded_cache(self):
        """op://./SSH Config/key resolves to an item name via the seeded cache."""
        registry = {
            ('work', 'my ssh key'): ('ssh-ed25519 DDDD', 'SHA256:selfref'),
        }
        op = MagicMock()
        op.read.return_value = 'op://Work/My SSH Key'
        meta = ItemMeta(vault_id='v1', item_id='i1')
        host = HostConfig(
            aliases=['tunnel'],
            hostname=fv('10.0.0.1', 'hostname'),
            key_ref='op://./SSH Config/key',
        )
        result = _resolve_key_ref(host, registry, op, meta)
        assert result.public_key == 'ssh-ed25519 DDDD'
        assert result.fingerprint == 'SHA256:selfref'
        op.read.assert_called_once_with('op://v1/i1/SSH Config/key', cache_only=True)

    def test_self_ref_cache_miss(self, capsys):
        """Self-ref that can't be resolved from seeded cache prints error."""
        op = MagicMock()
        op.read.return_value = None
        meta = ItemMeta(vault_id='v1', item_id='i1')
        host = HostConfig(
            aliases=['tunnel'],
            hostname=fv('10.0.0.1', 'hostname'),
            key_ref='op://./SSH Config/key',
        )
        result = _resolve_key_ref(host, {}, op, meta)
        assert result.public_key is None
        err = capsys.readouterr().err
        assert 'could not be resolved' in err
        assert 'tunnel' in err

    def test_direct_op_ref_goes_straight_to_registry(self):
        """Non-self op:// key refs go directly to registry without resolution."""
        registry = {
            ('work', 'my ssh key'): ('ssh-ed25519 EEEE', 'SHA256:direct'),
        }
        op = MagicMock()
        meta = ItemMeta(vault_id='v1', item_id='i1')
        host = HostConfig(
            aliases=['myhost'],
            hostname=fv('10.0.0.1', 'hostname'),
            key_ref='op://Work/My SSH Key',
        )
        result = _resolve_key_ref(host, registry, op, meta)
        assert result.public_key == 'ssh-ed25519 EEEE'
        op.read.assert_not_called()


class TestCmdDebugKeyRef:
    def test_alias_with_key_reference(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        (runtime_dir / 'hosts.conf').write_text(SAMPLE_HOSTS_CONF)
        hd = {
            'prod': {
                'key': 'op://Work/ProdKey',
                'fields': {
                    'password': {'original': 'op://Work/ServerLogin/password', 'resolved': None, 'sensitive': True},
                },
            },
        }
        (runtime_dir / 'hostdata.json').write_text(json.dumps(hd))

        cmd_debug('prod', _make_settings(runtime_dir))
        output = capsys.readouterr().out

        assert 'Key: op://Work/ProdKey' in output
        assert 'NOT RESOLVED' not in output  # IdentityFile present in block
        assert 'password:' in output

    def test_key_ref_warns_when_not_resolved(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        # Host block without IdentityFile — key resolution failed
        conf = "# Generated\n\nHost myhost\n    HostName 10.0.0.1\n    User root\n"
        (runtime_dir / 'hosts.conf').write_text(conf)
        hd = {
            'myhost': {
                'key': 'op://Personal/MyKey',
                'fields': {},
            },
        }
        (runtime_dir / 'hostdata.json').write_text(json.dumps(hd))

        cmd_debug('myhost', _make_settings(runtime_dir))
        output = capsys.readouterr().out

        assert 'Key: op://Personal/MyKey' in output
        assert 'NOT RESOLVED' in output

    def test_field_resolution_status(self, runtime_dir: Path, capsys):
        runtime_dir.mkdir(parents=True)
        conf = "# Generated\n\nHost myhost\n    HostName new.example.com\n"
        (runtime_dir / 'hosts.conf').write_text(conf)
        hd = {
            'myhost': {
                'fields': {
                    'hostname': {'original': 'op://v1/i1/website', 'resolved': 'new.example.com', 'sensitive': False},
                    'password': {'original': 'ops://v1/i1/SSH Config/password', 'resolved': None, 'sensitive': True},
                },
            },
        }
        (runtime_dir / 'hostdata.json').write_text(json.dumps(hd))

        cmd_debug('myhost', _make_settings(runtime_dir))
        output = capsys.readouterr().out

        assert 'hostname: op://v1/i1/website' in output
        assert 'new.example.com' in output
        assert 'sensitive, resolved at SSH time' in output


class TestResolveHostFieldsStaleness:
    """Test that reference fields are re-resolved when the target value changes."""

    def test_stale_reference_detected_via_cache_lookup(self):
        """When original is unchanged but the target value changed, re-resolve."""
        op = MagicMock()
        # op.read with cache_only=True returns the fresh value (seeded from item)
        # op.read without cache_only resolves the reference fully
        def read_side_effect(ref, *, cache_only=False):
            return 'new.example.com'
        op.read.side_effect = read_side_effect

        meta = ItemMeta(vault_id='v1', item_id='i1')
        ref = 'op://v1/i1/SSH Config/website'
        host = HostConfig(
            aliases=['myhost'],
            hostname=FieldValue(original=ref, resolved=None, sensitive=False, field_type='reference'),
        )
        # Cached: same original, but old resolved value
        cached_fields = {
            'hostname': FieldValue(original=ref, resolved='old.example.com', sensitive=False, field_type='reference'),
        }
        result = resolve_host_fields(host, meta, cached_fields, op)
        assert result.hostname.resolved == 'new.example.com'

    def test_unchanged_reference_uses_cache(self):
        """When original unchanged and target value unchanged, use cache."""
        op = MagicMock()
        def read_side_effect(ref, *, cache_only=False):
            return 'same.example.com'
        op.read.side_effect = read_side_effect

        meta = ItemMeta(vault_id='v1', item_id='i1')
        ref = 'op://v1/i1/SSH Config/website'
        host = HostConfig(
            aliases=['myhost'],
            hostname=FieldValue(original=ref, resolved=None, sensitive=False, field_type='reference'),
        )
        cached_fields = {
            'hostname': FieldValue(original=ref, resolved='same.example.com', sensitive=False, field_type='reference'),
        }
        result = resolve_host_fields(host, meta, cached_fields, op)
        assert result.hostname.resolved == 'same.example.com'

    def test_unknown_reference_falls_back_to_cache(self):
        """When cache_only returns None (not seeded), trust the original comparison."""
        op = MagicMock()
        def read_side_effect(ref, *, cache_only=False):
            if cache_only:
                return None  # Not in read cache
            return 'resolved.example.com'
        op.read.side_effect = read_side_effect

        meta = ItemMeta(vault_id='v1', item_id='i1')
        ref = 'op://OtherVault/OtherItem/hostname'
        host = HostConfig(
            aliases=['myhost'],
            hostname=FieldValue(original=ref, resolved=None, sensitive=False, field_type='reference'),
        )
        cached_fields = {
            'hostname': FieldValue(original=ref, resolved='cached.example.com', sensitive=False, field_type='reference'),
        }
        result = resolve_host_fields(host, meta, cached_fields, op)
        # Should use cached value since cache_only returned None
        assert result.hostname.resolved == 'cached.example.com'


class TestWarnNoexecAskpass:
    def test_no_warning_on_exec_filesystem(self, tmp_path: Path, capsys):
        _warn_noexec_askpass(tmp_path)
        err = capsys.readouterr().err
        assert err == ''

    def test_warns_on_noexec(self, tmp_path: Path, capsys):
        # Mock statvfs to return ST_NOEXEC flag
        mock_result = MagicMock()
        mock_result.f_flag = os.ST_NOEXEC
        with patch('ssh_concierge.cli.os.statvfs', return_value=mock_result):
            _warn_noexec_askpass(tmp_path)
        err = capsys.readouterr().err
        assert 'noexec' in err.lower()
        assert 'askpass' in err.lower()

    def test_walks_up_to_existing_parent(self, tmp_path: Path, capsys):
        # Non-existent dir — should check parent
        deep_path = tmp_path / 'a' / 'b' / 'c'
        _warn_noexec_askpass(deep_path)
        err = capsys.readouterr().err
        assert err == ''  # tmp_path is exec, so no warning

    def test_oserror_silenced(self, capsys):
        with patch('ssh_concierge.cli.os.statvfs', side_effect=OSError('fail')):
            _warn_noexec_askpass(Path('/nonexistent'))
        err = capsys.readouterr().err
        assert err == ''
