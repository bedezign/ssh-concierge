"""Tests for ssh_concierge.argparse_ssh."""

from __future__ import annotations

import pytest

from ssh_concierge.argparse_ssh import extract_scp_host, extract_ssh_host


class TestExtractSshHost:
    def test_simple_host(self):
        assert extract_ssh_host(['myhost']) == 'myhost'

    def test_user_at_host(self):
        assert extract_ssh_host(['deploy@myhost']) == 'myhost'

    def test_with_command(self):
        assert extract_ssh_host(['myhost', 'uptime']) == 'myhost'

    def test_with_port(self):
        assert extract_ssh_host(['-p', '2222', 'myhost']) == 'myhost'

    def test_with_port_glued(self):
        assert extract_ssh_host(['-p2222', 'myhost']) == 'myhost'

    def test_with_verbose(self):
        assert extract_ssh_host(['-v', 'myhost']) == 'myhost'

    def test_with_multiple_flags(self):
        assert extract_ssh_host(['-v', '-N', '-T', 'myhost']) == 'myhost'

    def test_with_combined_flags(self):
        assert extract_ssh_host(['-vvv', 'myhost']) == 'myhost'

    def test_with_identity_file(self):
        assert extract_ssh_host(['-i', '/path/to/key', 'myhost']) == 'myhost'

    def test_with_login_name(self):
        assert extract_ssh_host(['-l', 'user', 'myhost']) == 'myhost'

    def test_with_proxy_jump(self):
        assert extract_ssh_host(['-J', 'bastion', 'myhost']) == 'myhost'

    def test_with_option_o(self):
        assert extract_ssh_host(['-o', 'StrictHostKeyChecking=no', 'myhost']) == 'myhost'

    def test_complex_args(self):
        args = ['-p', '2222', '-v', '-o', 'ConnectTimeout=5', 'deploy@myhost', 'uptime']
        assert extract_ssh_host(args) == 'myhost'

    def test_double_dash(self):
        assert extract_ssh_host(['--', 'myhost']) == 'myhost'

    def test_double_dash_with_user(self):
        assert extract_ssh_host(['--', 'user@myhost']) == 'myhost'

    def test_empty_args(self):
        assert extract_ssh_host([]) is None

    def test_only_options(self):
        assert extract_ssh_host(['-v', '-N']) is None

    def test_forward_with_bind(self):
        assert extract_ssh_host(['-L', '8080:localhost:80', 'myhost']) == 'myhost'

    def test_remote_forward(self):
        assert extract_ssh_host(['-R', '9090:localhost:80', 'myhost']) == 'myhost'

    def test_dynamic_forward(self):
        assert extract_ssh_host(['-D', '1080', 'myhost']) == 'myhost'

    def test_config_file(self):
        assert extract_ssh_host(['-F', '/path/to/config', 'myhost']) == 'myhost'

    def test_cipher(self):
        assert extract_ssh_host(['-c', 'aes256-ctr', 'myhost']) == 'myhost'


class TestExtractScpHost:
    def test_remote_source(self):
        assert extract_scp_host(['myhost:/path/file', '.']) == 'myhost'

    def test_remote_target(self):
        assert extract_scp_host(['localfile', 'myhost:/remote/path']) == 'myhost'

    def test_user_at_host(self):
        assert extract_scp_host(['user@myhost:/path', '.']) == 'myhost'

    def test_with_port(self):
        assert extract_scp_host(['-P', '2222', 'myhost:/file', '.']) == 'myhost'

    def test_with_identity(self):
        assert extract_scp_host(['-i', '/key', 'myhost:/file', '.']) == 'myhost'

    def test_with_option(self):
        assert extract_scp_host(['-o', 'StrictHostKeyChecking=no', 'myhost:/f', '.']) == 'myhost'

    def test_local_to_local(self):
        assert extract_scp_host(['file1', 'file2']) is None

    def test_empty_args(self):
        assert extract_scp_host([]) is None

    def test_absolute_path_not_remote(self):
        """Local absolute paths with colons should not match as remote."""
        assert extract_scp_host(['/path/to/file:with:colons', 'dest']) is None

    def test_recursive_flag(self):
        assert extract_scp_host(['-r', 'myhost:/dir', '.']) == 'myhost'

    def test_complex_args(self):
        args = ['-P', '22', '-i', '/key', '-o', 'Opt=val', 'user@server:/file', '/local']
        assert extract_scp_host(args) == 'server'

    def test_with_jump_host(self):
        assert extract_scp_host(['-J', 'bastion', 'myhost:/file', '.']) == 'myhost'
