"""Tests for ssh_concierge.config."""

import json
import os
import stat
import textwrap
from pathlib import Path

from tests.conftest import fv

import pytest

from ssh_concierge.config import generate_host_block, generate_runtime_config
from ssh_concierge.models import HostConfig


def _key_file(keys_dir: Path):
    """Return a key_file callable rooted at keys_dir."""
    def _inner(fingerprint: str) -> Path:
        return keys_dir / f'{fingerprint.replace("/", "_")}.pub'
    return _inner


def _gen(hosts, tmp_path, *, hostdata=None, key_mode=0o600):
    """Shorthand for generate_runtime_config with paths derived from tmp_path."""
    generate_runtime_config(
        hosts,
        runtime_dir=tmp_path,
        keys_dir=tmp_path / 'keys',
        hosts_file=tmp_path / 'hosts.conf',
        hostdata_file=tmp_path / 'hostdata.json',
        key_file=_key_file(tmp_path / 'keys'),
        hostdata=hostdata,
        key_mode=key_mode,
    )


class TestGenerateHostBlock:
    def test_minimal_host(self):
        host = HostConfig(aliases=["myserver"], hostname=fv("10.0.0.1", "hostname"))
        kf = _key_file(Path("/run/user/1000/ssh-concierge/keys"))
        block = generate_host_block(host, kf)
        expected = textwrap.dedent("""\
            Host myserver
                HostName 10.0.0.1
        """)
        assert block == expected

    def test_full_host(self):
        host = HostConfig(
            aliases=["prod", "prod-web-01"],
            hostname=fv("203.0.113.42", "hostname"),
            port=fv("2222", "port"),
            user=fv("deploy", "user"),
            public_key="ssh-ed25519 AAAAC3... comment",
            fingerprint="SHA256:abc123",
        )
        kf = _key_file(Path("/run/user/1000/ssh-concierge/keys"))
        block = generate_host_block(host, kf)
        assert "Host prod prod-web-01\n" in block
        assert "    HostName 203.0.113.42\n" in block
        assert "    Port 2222\n" in block
        assert "    User deploy\n" in block
        assert "    IdentityFile /run/user/1000/ssh-concierge/keys/SHA256:abc123.pub\n" in block
        assert "IdentitiesOnly" not in block

    def test_hostname_defaults_to_first_alias(self):
        host = HostConfig(aliases=["bastion.example.com", "bastion"])
        block = generate_host_block(host, _key_file(Path("/keys")))
        assert "    HostName bastion.example.com\n" in block

    def test_extra_directives(self):
        host = HostConfig(
            aliases=["jump"],
            hostname=fv("10.0.0.1", "hostname"),
            extra_directives={
                "ProxyJump": fv("bastion", "ProxyJump"),
                "ForwardAgent": fv("yes", "ForwardAgent"),
            },
        )
        block = generate_host_block(host, _key_file(Path("/keys")))
        assert "    ProxyJump bastion\n" in block
        assert "    ForwardAgent yes\n" in block

    def test_backslash_percent_escaped_in_user(self):
        r"""Only \% is converted to %% — bare % passes through."""
        host = HostConfig(
            aliases=["server1"],
            hostname=fv("pam-gateway.example.com", "hostname"),
            user=fv(r"jdoe@pajdoe\%corp.example.com@server1.example.com", "user"),
        )
        block = generate_host_block(host, _key_file(Path("/keys")))
        assert "    User jdoe@pajdoe%%corp.example.com@server1.example.com\n" in block

    def test_bare_percent_not_escaped_in_user(self):
        """Bare % in User passes through unchanged (SSH token)."""
        host = HostConfig(
            aliases=["server1"],
            hostname=fv("pam-gateway.example.com", "hostname"),
            user=fv("jdoe@pajdoe%corp.example.com@server1.example.com", "user"),
        )
        block = generate_host_block(host, _key_file(Path("/keys")))
        assert "    User jdoe@pajdoe%corp.example.com@server1.example.com\n" in block

    def test_percent_tokens_preserved_in_extra_directives(self):
        """SSH percent tokens (%h, %r, %p) pass through unchanged."""
        host = HostConfig(
            aliases=["test"],
            hostname=fv("10.0.0.1", "hostname"),
            extra_directives={"ControlPath": fv("/tmp/ssh-%r@%h:%p", "ControlPath")},
        )
        block = generate_host_block(host, _key_file(Path("/keys")))
        assert "    ControlPath /tmp/ssh-%r@%h:%p\n" in block

    def test_backslash_percent_escaped_in_extra_directives(self):
        r"""The \% escape works in extra directives too."""
        host = HostConfig(
            aliases=["test"],
            hostname=fv("10.0.0.1", "hostname"),
            extra_directives={"RemoteCommand": fv(r"echo 100\% done", "RemoteCommand")},
        )
        block = generate_host_block(host, _key_file(Path("/keys")))
        assert "    RemoteCommand echo 100%% done\n" in block

    def test_percent_not_escaped_in_hostname(self):
        host = HostConfig(aliases=["master1"], hostname=fv("%h.cluster1.example.com", "hostname"))
        block = generate_host_block(host, _key_file(Path("/keys")))
        assert "    HostName %h.cluster1.example.com\n" in block

    def test_no_identity_without_public_key(self):
        host = HostConfig(aliases=["test"], hostname=fv("10.0.0.1", "hostname"))
        block = generate_host_block(host, _key_file(Path("/keys")))
        assert "IdentityFile" not in block
        assert "IdentitiesOnly" not in block


class TestGenerateRuntimeConfig:
    def test_creates_hosts_conf(self, tmp_path: Path):
        hosts = [
            HostConfig(aliases=["server1"], hostname=fv("10.0.0.1", "hostname")),
            HostConfig(aliases=["server2"], hostname=fv("10.0.0.2", "hostname"), user=fv("admin", "user")),
        ]
        _gen(hosts, tmp_path)

        conf = tmp_path / "hosts.conf"
        assert conf.exists()
        content = conf.read_text()
        assert "Host server1" in content
        assert "Host server2" in content
        assert "User admin" in content

    def test_creates_key_files(self, tmp_path: Path):
        hosts = [
            HostConfig(
                aliases=["keyed"],
                hostname=fv("10.0.0.1", "hostname"),
                public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample comment",
                fingerprint="SHA256:xyzzy",
            ),
        ]
        _gen(hosts, tmp_path)

        key_file = tmp_path / "keys" / "SHA256:xyzzy.pub"
        assert key_file.exists()
        assert key_file.read_text() == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample comment\n"

    def test_key_file_permissions_default(self, tmp_path: Path):
        hosts = [
            HostConfig(
                aliases=["keyed"],
                hostname=fv("10.0.0.1", "hostname"),
                public_key="ssh-ed25519 AAAA... comment",
                fingerprint="SHA256:abc",
            ),
        ]
        _gen(hosts, tmp_path)

        key_file = tmp_path / "keys" / "SHA256:abc.pub"
        mode = key_file.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_key_file_permissions_custom(self, tmp_path: Path):
        hosts = [
            HostConfig(
                aliases=["keyed"],
                hostname=fv("10.0.0.1", "hostname"),
                public_key="ssh-ed25519 AAAA... comment",
                fingerprint="SHA256:abc",
            ),
        ]
        _gen(hosts, tmp_path, key_mode=0o644)

        key_file = tmp_path / "keys" / "SHA256:abc.pub"
        mode = key_file.stat().st_mode
        assert stat.S_IMODE(mode) == 0o644

    def test_empty_hosts_produces_empty_conf(self, tmp_path: Path):
        _gen([], tmp_path)

        conf = tmp_path / "hosts.conf"
        assert conf.exists()
        assert conf.read_text().strip() == "# Generated by ssh-concierge — do not edit"

    def test_atomic_write(self, tmp_path: Path):
        """Config file should appear atomically (no partial writes visible)."""
        hosts = [HostConfig(aliases=["test"], hostname=fv("10.0.0.1", "hostname"))]

        # Write initial config
        _gen(hosts, tmp_path)
        conf = tmp_path / "hosts.conf"

        # Overwrite — should be atomic
        hosts2 = [HostConfig(aliases=["other"], hostname=fv("10.0.0.2", "hostname"))]
        _gen(hosts2, tmp_path)
        new_content = conf.read_text()

        assert "Host other" in new_content
        assert "Host test" not in new_content

    def test_keys_dir_created(self, tmp_path: Path):
        _gen([], tmp_path)
        assert (tmp_path / "keys").is_dir()

    def test_multiple_hosts_with_keys(self, tmp_path: Path):
        hosts = [
            HostConfig(
                aliases=["a"],
                hostname=fv("10.0.0.1", "hostname"),
                public_key="ssh-rsa AAAAkey1 c1",
                fingerprint="SHA256:key1",
            ),
            HostConfig(
                aliases=["b"],
                hostname=fv("10.0.0.2", "hostname"),
                public_key="ssh-ed25519 AAAAkey2 c2",
                fingerprint="SHA256:key2",
            ),
        ]
        _gen(hosts, tmp_path)

        assert (tmp_path / "keys" / "SHA256:key1.pub").exists()
        assert (tmp_path / "keys" / "SHA256:key2.pub").exists()

        content = (tmp_path / "hosts.conf").read_text()
        assert "Host a" in content
        assert "Host b" in content

    def test_hostdata_json_written(self, tmp_path: Path):
        hosts = [HostConfig(aliases=["myhost"], hostname=fv("10.0.0.1", "hostname"))]
        hd = {"myhost": {"refs": {"password": "op://vault/item/password"}}}
        _gen(hosts, tmp_path, hostdata=hd)

        hd_path = tmp_path / "hostdata.json"
        assert hd_path.exists()
        data = json.loads(hd_path.read_text())
        assert data == hd

    def test_hostdata_json_not_written_without_data(self, tmp_path: Path):
        hosts = [HostConfig(aliases=["h"], hostname=fv("10.0.0.1", "hostname"))]
        _gen(hosts, tmp_path)
        assert not (tmp_path / "hostdata.json").exists()

    def test_hostdata_json_removed_when_empty(self, tmp_path: Path):
        hosts = [HostConfig(aliases=["h"], hostname=fv("10.0.0.1", "hostname"))]
        hd = {"h": {"refs": {"password": "op://v/i/pw"}}}
        _gen(hosts, tmp_path, hostdata=hd)
        assert (tmp_path / "hostdata.json").exists()
        # Regenerate without hostdata
        _gen(hosts, tmp_path)
        assert not (tmp_path / "hostdata.json").exists()

    def test_hostdata_json_with_clipboard(self, tmp_path: Path):
        hosts = [HostConfig(aliases=["h"], hostname=fv("10.0.0.1", "hostname"))]
        hd = {
            "h": {
                "refs": {"password": "op://v/i/pw"},
                "clipboard": "sudo -i\\n{password}\\n",
            },
        }
        _gen(hosts, tmp_path, hostdata=hd)

        data = json.loads((tmp_path / "hostdata.json").read_text())
        assert data["h"]["clipboard"] == "sudo -i\\n{password}\\n"
        assert data["h"]["refs"]["password"] == "op://v/i/pw"

    def test_hostdata_json_multiple_aliases(self, tmp_path: Path):
        hosts = [HostConfig(aliases=["a", "b"], hostname=fv("10.0.0.1", "hostname"))]
        entry = {"refs": {"password": "op://v/i/SSH Config/password"}}
        hd = {"a": entry, "b": entry}
        _gen(hosts, tmp_path, hostdata=hd)

        data = json.loads((tmp_path / "hostdata.json").read_text())
        assert data["a"] == data["b"]
