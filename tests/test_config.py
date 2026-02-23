"""Tests for ssh_concierge.config."""

import json
import os
import stat
import textwrap
from pathlib import Path

import pytest

from ssh_concierge.config import generate_host_block, generate_runtime_config
from ssh_concierge.models import HostConfig


class TestGenerateHostBlock:
    def test_minimal_host(self):
        host = HostConfig(aliases=["myserver"], hostname="10.0.0.1")
        block = generate_host_block(host, keys_dir=Path("/run/user/1000/ssh-concierge/keys"))
        expected = textwrap.dedent("""\
            Host myserver
                HostName 10.0.0.1
        """)
        assert block == expected

    def test_full_host(self):
        host = HostConfig(
            aliases=["prod", "prod-web-01"],
            hostname="203.0.113.42",
            port="2222",
            user="deploy",
            public_key="ssh-ed25519 AAAAC3... comment",
            fingerprint="SHA256:abc123",
        )
        block = generate_host_block(host, keys_dir=Path("/run/user/1000/ssh-concierge/keys"))
        assert "Host prod prod-web-01\n" in block
        assert "    HostName 203.0.113.42\n" in block
        assert "    Port 2222\n" in block
        assert "    User deploy\n" in block
        assert "    IdentityFile /run/user/1000/ssh-concierge/keys/SHA256:abc123.pub\n" in block
        assert "    IdentitiesOnly yes\n" in block

    def test_hostname_defaults_to_first_alias(self):
        host = HostConfig(aliases=["bastion.example.com", "bastion"])
        block = generate_host_block(host, keys_dir=Path("/keys"))
        assert "    HostName bastion.example.com\n" in block

    def test_extra_directives(self):
        host = HostConfig(
            aliases=["jump"],
            hostname="10.0.0.1",
            extra_directives={"ProxyJump": "bastion", "ForwardAgent": "yes"},
        )
        block = generate_host_block(host, keys_dir=Path("/keys"))
        assert "    ProxyJump bastion\n" in block
        assert "    ForwardAgent yes\n" in block

    def test_percent_escaped_in_user(self):
        host = HostConfig(
            aliases=["server1"],
            hostname="pam-gateway.example.com",
            user="jdoe@pajdoe%corp.example.com@server1.example.com",
        )
        block = generate_host_block(host, keys_dir=Path("/keys"))
        assert "    User jdoe@pajdoe%%corp.example.com@server1.example.com\n" in block

    def test_percent_escaped_in_extra_directives(self):
        host = HostConfig(
            aliases=["test"],
            hostname="10.0.0.1",
            extra_directives={"RemoteCommand": "echo %done"},
        )
        block = generate_host_block(host, keys_dir=Path("/keys"))
        assert "    RemoteCommand echo %%done\n" in block

    def test_percent_not_escaped_in_hostname(self):
        host = HostConfig(aliases=["master1"], hostname="%h.cluster1.example.com")
        block = generate_host_block(host, keys_dir=Path("/keys"))
        assert "    HostName %h.cluster1.example.com\n" in block

    def test_no_identity_without_public_key(self):
        host = HostConfig(aliases=["test"], hostname="10.0.0.1")
        block = generate_host_block(host, keys_dir=Path("/keys"))
        assert "IdentityFile" not in block
        assert "IdentitiesOnly" not in block


class TestGenerateRuntimeConfig:
    def test_creates_hosts_conf(self, tmp_path: Path):
        hosts = [
            HostConfig(aliases=["server1"], hostname="10.0.0.1"),
            HostConfig(aliases=["server2"], hostname="10.0.0.2", user="admin"),
        ]
        generate_runtime_config(hosts, runtime_dir=tmp_path)

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
                hostname="10.0.0.1",
                public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample comment",
                fingerprint="SHA256:xyzzy",
            ),
        ]
        generate_runtime_config(hosts, runtime_dir=tmp_path)

        key_file = tmp_path / "keys" / "SHA256:xyzzy.pub"
        assert key_file.exists()
        assert key_file.read_text() == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample comment\n"

    def test_key_file_permissions(self, tmp_path: Path):
        hosts = [
            HostConfig(
                aliases=["keyed"],
                hostname="10.0.0.1",
                public_key="ssh-ed25519 AAAA... comment",
                fingerprint="SHA256:abc",
            ),
        ]
        generate_runtime_config(hosts, runtime_dir=tmp_path)

        key_file = tmp_path / "keys" / "SHA256:abc.pub"
        mode = key_file.stat().st_mode
        assert stat.S_IMODE(mode) == 0o644

    def test_empty_hosts_produces_empty_conf(self, tmp_path: Path):
        generate_runtime_config([], runtime_dir=tmp_path)

        conf = tmp_path / "hosts.conf"
        assert conf.exists()
        assert conf.read_text().strip() == "# Generated by ssh-concierge — do not edit"

    def test_atomic_write(self, tmp_path: Path):
        """Config file should appear atomically (no partial writes visible)."""
        hosts = [HostConfig(aliases=["test"], hostname="10.0.0.1")]

        # Write initial config
        generate_runtime_config(hosts, runtime_dir=tmp_path)
        conf = tmp_path / "hosts.conf"
        initial_content = conf.read_text()

        # Overwrite — should be atomic
        hosts2 = [HostConfig(aliases=["other"], hostname="10.0.0.2")]
        generate_runtime_config(hosts2, runtime_dir=tmp_path)
        new_content = conf.read_text()

        assert "Host other" in new_content
        assert "Host test" not in new_content

    def test_keys_dir_created(self, tmp_path: Path):
        generate_runtime_config([], runtime_dir=tmp_path)
        assert (tmp_path / "keys").is_dir()

    def test_multiple_hosts_with_keys(self, tmp_path: Path):
        hosts = [
            HostConfig(
                aliases=["a"],
                hostname="10.0.0.1",
                public_key="ssh-rsa AAAAkey1 c1",
                fingerprint="SHA256:key1",
            ),
            HostConfig(
                aliases=["b"],
                hostname="10.0.0.2",
                public_key="ssh-ed25519 AAAAkey2 c2",
                fingerprint="SHA256:key2",
            ),
        ]
        generate_runtime_config(hosts, runtime_dir=tmp_path)

        assert (tmp_path / "keys" / "SHA256:key1.pub").exists()
        assert (tmp_path / "keys" / "SHA256:key2.pub").exists()

        content = (tmp_path / "hosts.conf").read_text()
        assert "Host a" in content
        assert "Host b" in content

    def test_passwords_json_written(self, tmp_path: Path):
        hosts = [HostConfig(aliases=["myhost"], hostname="10.0.0.1")]
        refs = {"myhost": "op://vault/item/password"}
        generate_runtime_config(hosts, runtime_dir=tmp_path, password_refs=refs)

        pw_path = tmp_path / "passwords.json"
        assert pw_path.exists()
        data = json.loads(pw_path.read_text())
        assert data == {"myhost": "op://vault/item/password"}

    def test_passwords_json_permissions(self, tmp_path: Path):
        hosts = [HostConfig(aliases=["h"], hostname="10.0.0.1")]
        refs = {"h": "op://v/i/pw"}
        generate_runtime_config(hosts, runtime_dir=tmp_path, password_refs=refs)

        pw_path = tmp_path / "passwords.json"
        mode = stat.S_IMODE(pw_path.stat().st_mode)
        assert mode == 0o600

    def test_passwords_json_not_written_without_refs(self, tmp_path: Path):
        hosts = [HostConfig(aliases=["h"], hostname="10.0.0.1")]
        generate_runtime_config(hosts, runtime_dir=tmp_path)
        assert not (tmp_path / "passwords.json").exists()

    def test_passwords_json_removed_when_no_refs(self, tmp_path: Path):
        hosts = [HostConfig(aliases=["h"], hostname="10.0.0.1")]
        # First create with refs
        generate_runtime_config(hosts, tmp_path, password_refs={"h": "op://v/i/pw"})
        assert (tmp_path / "passwords.json").exists()
        # Then regenerate without refs
        generate_runtime_config(hosts, tmp_path)
        assert not (tmp_path / "passwords.json").exists()

    def test_passwords_json_multiple_aliases(self, tmp_path: Path):
        hosts = [HostConfig(aliases=["a", "b"], hostname="10.0.0.1")]
        refs = {
            "a": "op://v/i/SSH Config/password",
            "b": "op://v/i/SSH Config/password",
        }
        generate_runtime_config(hosts, runtime_dir=tmp_path, password_refs=refs)

        data = json.loads((tmp_path / "passwords.json").read_text())
        assert data["a"] == data["b"]
