"""Tests for ssh_concierge.deploy."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ssh_concierge.deploy import (
    _build_ssh_copy_id_args,
    cmd_deploy_key,
    deploy_key_to_host,
    find_siblings,
    resolve_host,
)
from ssh_concierge.models import HostConfig
from ssh_concierge.password import ItemMeta
from ssh_concierge.settings import Settings
from tests.conftest import fv

# --- fixtures ---


def _host(
    aliases: list[str],
    *,
    fingerprint: str = "SHA256:abc",
    section_label: str = "SSH Config: cluster",
    public_key: str = "ssh-ed25519 AAAAkey",
    hostname: str | None = None,
    port: str | None = None,
    user: str | None = None,
    password: str | None = None,
) -> HostConfig:
    return HostConfig(
        aliases=aliases,
        hostname=fv(hostname, "hostname") if hostname else None,
        port=fv(port, "port") if port else None,
        user=fv(user, "user") if user else None,
        public_key=public_key,
        fingerprint=fingerprint,
        section_label=section_label,
        password=fv(password, "password") if password else None,
    )


DEFAULT_META = ItemMeta(vault_id="vault-1", item_id="item-1")

WORKER1 = _host(["worker1"], hostname="worker1.example.com")
WORKER2 = _host(["worker2"], hostname="worker2.example.com")
WORKER3 = _host(["worker3"], hostname="worker3.example.com")
WILDCARD = _host(["*.example.com"], hostname="%h")
OTHER_SECTION = _host(
    ["web1"],
    section_label="SSH Config: web",
    fingerprint="SHA256:abc",
)
OTHER_KEY = _host(
    ["db1"],
    section_label="SSH Config: cluster",
    fingerprint="SHA256:different",
)

ALL_HOSTS = [
    (WORKER1, DEFAULT_META),
    (WORKER2, DEFAULT_META),
    (WORKER3, DEFAULT_META),
    (WILDCARD, DEFAULT_META),
    (OTHER_SECTION, DEFAULT_META),
    (OTHER_KEY, DEFAULT_META),
]


def _make_settings(runtime_dir: Path) -> Settings:
    return Settings(
        runtime_dir=runtime_dir,
        askpass_dir=runtime_dir,
        ttl=3600,
        op_timeout=120,
        config_file=None,
    )


@pytest.fixture()
def runtime_dir(tmp_path: Path) -> Path:
    d = tmp_path / "ssh-concierge"
    d.mkdir()
    keys = d / "keys"
    keys.mkdir()
    (keys / "SHA256:abc.pub").write_text("ssh-ed25519 AAAAkey\n")
    return d


@pytest.fixture()
def settings(runtime_dir: Path) -> Settings:
    return _make_settings(runtime_dir)


# --- resolve_host ---


class TestResolveHost:
    def test_finds_by_alias(self):
        result = resolve_host("worker2", ALL_HOSTS)
        assert result is not None
        assert result[0] is WORKER2

    def test_not_found(self):
        assert resolve_host("nonexistent", ALL_HOSTS) is None

    def test_finds_first_match(self):
        host1 = _host(["shared", "alias2"])
        host2 = _host(["shared", "alias3"])
        hosts = [(host1, DEFAULT_META), (host2, DEFAULT_META)]
        result = resolve_host("shared", hosts)
        assert result is not None
        assert result[0] is host1


# --- find_siblings ---


class TestFindSiblings:
    def test_finds_same_section_and_fingerprint(self):
        siblings = find_siblings(WORKER1, ALL_HOSTS)
        sibling_hosts = [s for s, _ in siblings]
        assert WORKER2 in sibling_hosts
        assert WORKER3 in sibling_hosts

    def test_excludes_self(self):
        siblings = find_siblings(WORKER1, ALL_HOSTS)
        sibling_hosts = [s for s, _ in siblings]
        assert WORKER1 not in sibling_hosts

    def test_excludes_wildcards(self):
        siblings = find_siblings(WORKER1, ALL_HOSTS)
        sibling_hosts = [s for s, _ in siblings]
        assert WILDCARD not in sibling_hosts

    def test_excludes_different_section(self):
        siblings = find_siblings(WORKER1, ALL_HOSTS)
        sibling_hosts = [s for s, _ in siblings]
        assert OTHER_SECTION not in sibling_hosts

    def test_excludes_different_fingerprint(self):
        siblings = find_siblings(WORKER1, ALL_HOSTS)
        sibling_hosts = [s for s, _ in siblings]
        assert OTHER_KEY not in sibling_hosts


# --- _build_ssh_copy_id_args ---


class TestBuildSshCopyIdArgs:
    def test_basic(self):
        host = _host(["myhost"])
        key = Path("/tmp/key.pub")
        args = _build_ssh_copy_id_args(host, key)
        assert args == ["ssh-copy-id", "-i", "/tmp/key.pub", "myhost"]

    def test_with_port(self):
        host = _host(["myhost"], port="2222")
        key = Path("/tmp/key.pub")
        args = _build_ssh_copy_id_args(host, key)
        assert args == ["ssh-copy-id", "-i", "/tmp/key.pub", "-p", "2222", "myhost"]

    def test_with_user(self):
        host = _host(["myhost"], user="deploy")
        key = Path("/tmp/key.pub")
        args = _build_ssh_copy_id_args(host, key)
        assert args == ["ssh-copy-id", "-i", "/tmp/key.pub", "deploy@myhost"]

    def test_with_port_and_user(self):
        host = _host(["myhost"], port="2222", user="deploy")
        key = Path("/tmp/key.pub")
        args = _build_ssh_copy_id_args(host, key)
        assert args == [
            "ssh-copy-id",
            "-i",
            "/tmp/key.pub",
            "-p",
            "2222",
            "deploy@myhost",
        ]


# --- deploy_key_to_host ---


class TestDeployKeyToHost:
    @patch("ssh_concierge.deploy.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        host = _host(["myhost"])
        assert deploy_key_to_host(host, Path("/tmp/key.pub")) is True

    @patch("ssh_concierge.deploy.subprocess.run")
    def test_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        host = _host(["myhost"])
        assert deploy_key_to_host(host, Path("/tmp/key.pub")) is False

    @patch("ssh_concierge.deploy.subprocess.run", side_effect=FileNotFoundError)
    def test_ssh_copy_id_not_found(self, mock_run):
        host = _host(["myhost"])
        assert deploy_key_to_host(host, Path("/tmp/key.pub")) is False

    @patch("ssh_concierge.deploy.subprocess.run")
    def test_with_password_uses_askpass(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        host = _host(["myhost"])
        result = deploy_key_to_host(
            host,
            Path("/tmp/key.pub"),
            password="secret",
            askpass_file=tmp_path / "askpass",
        )
        assert result is True
        call_args = mock_run.call_args
        # Should use ssh-copy-id directly (no setsid)
        assert call_args[0][0][0] == "ssh-copy-id"
        # Should have SSH_ASKPASS in env
        env = call_args[1].get("env", {})
        assert "SSH_ASKPASS" in env
        assert env["SSH_ASKPASS_REQUIRE"] == "force"

    @patch("ssh_concierge.deploy.subprocess.run")
    def test_without_password_inherits_stdin(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        host = _host(["myhost"])
        deploy_key_to_host(host, Path("/tmp/key.pub"))
        call_args = mock_run.call_args
        # No setsid prefix
        assert call_args[0][0][0] == "ssh-copy-id"


# --- cmd_deploy_key ---


class TestCmdDeployKey:
    @patch("ssh_concierge.deploy.fetch_all_hosts", return_value=(ALL_HOSTS, []))
    @patch("ssh_concierge.deploy.deploy_key_to_host", return_value=True)
    @patch("ssh_concierge.deploy._resolve_password", return_value=None)
    def test_single_host(self, mock_resolve_pw, mock_deploy, mock_fetch, settings):
        cmd_deploy_key("worker1", False, settings)
        mock_deploy.assert_called_once()
        deployed_host = mock_deploy.call_args[0][0]
        assert deployed_host.aliases == ["worker1"]

    @patch("ssh_concierge.deploy.fetch_all_hosts", return_value=(ALL_HOSTS, []))
    @patch("ssh_concierge.deploy.deploy_key_to_host", return_value=True)
    @patch("ssh_concierge.deploy._resolve_password", return_value=None)
    def test_all_siblings(self, mock_resolve_pw, mock_deploy, mock_fetch, settings):
        cmd_deploy_key("worker1", True, settings)
        # worker1 + worker2 + worker3 (not wildcard, not other section/key)
        assert mock_deploy.call_count == 3
        deployed_aliases = [
            call[0][0].aliases[0] for call in mock_deploy.call_args_list
        ]
        assert "worker1" in deployed_aliases
        assert "worker2" in deployed_aliases
        assert "worker3" in deployed_aliases

    @patch("ssh_concierge.deploy.fetch_all_hosts", return_value=(ALL_HOSTS, []))
    def test_alias_not_found(self, mock_fetch, settings):
        with pytest.raises(SystemExit) as exc_info:
            cmd_deploy_key("nonexistent", False, settings)
        assert exc_info.value.code == 1

    @patch("ssh_concierge.deploy.fetch_all_hosts", return_value=(ALL_HOSTS, []))
    @patch("ssh_concierge.deploy.deploy_key_to_host")
    @patch("ssh_concierge.deploy._resolve_password", return_value=None)
    def test_partial_failure(self, mock_resolve_pw, mock_deploy, mock_fetch, settings):
        mock_deploy.side_effect = [True, False, True]
        with pytest.raises(SystemExit) as exc_info:
            cmd_deploy_key("worker1", True, settings)
        assert exc_info.value.code == 1

    @patch("ssh_concierge.deploy.fetch_all_hosts")
    def test_no_key_on_host(self, mock_fetch, settings):
        host_no_key = HostConfig(
            aliases=["nokey"],
            section_label="SSH Config",
        )
        mock_fetch.return_value = ([(host_no_key, DEFAULT_META)], [])
        with pytest.raises(SystemExit) as exc_info:
            cmd_deploy_key("nokey", False, settings)
        assert exc_info.value.code == 1

    @patch("ssh_concierge.deploy.fetch_all_hosts")
    @patch("ssh_concierge.deploy.deploy_key_to_host", return_value=True)
    @patch("ssh_concierge.deploy._resolve_password", return_value="resolved-pw")
    def test_password_passed_to_deploy(
        self, mock_resolve_pw, mock_deploy, mock_fetch, settings
    ):
        host_with_pw = _host(["pwhost"], password="op://././password")
        mock_fetch.return_value = ([(host_with_pw, DEFAULT_META)], [])
        cmd_deploy_key("pwhost", False, settings)
        mock_deploy.assert_called_once()
        assert mock_deploy.call_args[1]["password"] == "resolved-pw"

    @patch("ssh_concierge.deploy.fetch_all_hosts")
    @patch("ssh_concierge.deploy.deploy_key_to_host", return_value=True)
    @patch("ssh_concierge.deploy._resolve_password", return_value="shared-pw")
    def test_all_siblings_share_resolved_password(
        self, mock_resolve_pw, mock_deploy, mock_fetch, settings
    ):
        """Password resolved once and reused for all siblings."""
        hosts = [
            (_host(["s1"], password="op://././password"), DEFAULT_META),
            (_host(["s2"], password="op://././password"), DEFAULT_META),
        ]
        mock_fetch.return_value = (hosts, [])
        cmd_deploy_key("s1", True, settings)
        # _resolve_password called once
        mock_resolve_pw.assert_called_once()
        # Both deploys get the same resolved password
        for call in mock_deploy.call_args_list:
            assert call[1]["password"] == "shared-pw"
