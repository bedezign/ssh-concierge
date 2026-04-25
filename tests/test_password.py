"""Tests for ssh_concierge.password."""

from __future__ import annotations

import stat
from pathlib import Path

from ssh_concierge.password import (
    _build_askpass_script,
    create_askpass,
)


class TestCreateAskpass:
    def test_returns_correct_env_vars(self, tmp_path):
        env = create_askpass("mypassword", askpass_file=tmp_path / "askpass")
        assert "SSH_ASKPASS" in env
        assert env["SSH_ASKPASS_REQUIRE"] == "force"
        assert env["__SSH_CONCIERGE_PW"] == "mypassword"
        script = Path(env["SSH_ASKPASS"])
        assert script.exists()
        assert script.stat().st_mode & stat.S_IRWXU == stat.S_IRWXU

    def test_script_is_generic(self, tmp_path):
        """Script contains no password — only reads from env var."""
        env = create_askpass("s3cret", askpass_file=tmp_path / "askpass")
        content = Path(env["SSH_ASKPASS"]).read_text()
        assert "s3cret" not in content
        assert "__SSH_CONCIERGE_PW" in content

    def test_script_reused_across_calls(self, tmp_path):
        """Same script file is reused for different passwords."""
        env1 = create_askpass("pw1", askpass_file=tmp_path / "askpass")
        env2 = create_askpass("pw2", askpass_file=tmp_path / "askpass")
        assert env1["SSH_ASKPASS"] == env2["SSH_ASKPASS"]
        assert env1["__SSH_CONCIERGE_PW"] == "pw1"
        assert env2["__SSH_CONCIERGE_PW"] == "pw2"

    def test_script_outputs_password(self, tmp_path):
        """Running the script with a password prompt outputs the password."""
        import subprocess

        pw = "testpw123"
        env = create_askpass(pw, askpass_file=tmp_path / "askpass")
        result = subprocess.run(
            [env["SSH_ASKPASS"], "user@host's password: "],
            capture_output=True,
            text=True,
            env={"__SSH_CONCIERGE_PW": pw},
        )
        assert result.stdout.rstrip("\n") == pw

    def test_password_with_dollar_and_backtick(self, tmp_path):
        """Verify shell metacharacters are preserved literally via env var."""
        import subprocess

        pw = '$HOME `whoami` "quoted" \\backslash'
        env = create_askpass(pw, askpass_file=tmp_path / "askpass")
        result = subprocess.run(
            [env["SSH_ASKPASS"], "Password: "],
            capture_output=True,
            text=True,
            env={"__SSH_CONCIERGE_PW": pw},
        )
        assert result.stdout.rstrip("\n") == pw

    def test_non_password_prompt_passes_through(self, tmp_path):
        """Non-password prompts are forwarded to the terminal via /dev/tty."""
        import subprocess

        env = create_askpass("secret", askpass_file=tmp_path / "askpass")
        # Simulate a host key prompt — no /dev/tty in test, so the script
        # will fail to write to /dev/tty and exit non-zero.
        result = subprocess.run(
            [
                env["SSH_ASKPASS"],
                "Are you sure you want to continue connecting (yes/no)? ",
            ],
            capture_output=True,
            text=True,
            env={"__SSH_CONCIERGE_PW": "secret"},
        )
        # Should NOT output the password for non-password prompts
        assert "secret" not in result.stdout


class TestBuildAskpassScript:
    def test_default_patterns(self):
        script = _build_askpass_script()
        assert "*assword*" in script
        assert "__SSH_CONCIERGE_PW" in script
        assert "__SSH_CONCIERGE_PW_PROMPT" in script

    def test_custom_password_patterns(self):
        script = _build_askpass_script(password_patterns=("*assword*", "*ASSWORD*"))
        assert "*assword*|*ASSWORD*" in script

    def test_otp_patterns_included(self):
        script = _build_askpass_script(
            otp_patterns=("*erification*code*", "*one-time*")
        )
        assert "*erification*code*|*one-time*" in script
        assert "__SSH_CONCIERGE_OTP" in script

    def test_empty_password_patterns(self):
        script = _build_askpass_script(password_patterns=())
        # Should still have catch-all and OTP env var blocks
        assert "__SSH_CONCIERGE_PW_PROMPT" in script
        assert "unrecognized prompt" in script

    def test_per_host_override_blocks_present(self):
        script = _build_askpass_script()
        assert "__SSH_CONCIERGE_PW_PROMPT" in script
        assert "__SSH_CONCIERGE_OTP_PROMPT" in script

    def test_catch_all_present(self):
        script = _build_askpass_script()
        assert "unrecognized prompt" in script


class TestAskpassScriptExecution:
    """Tests that actually run the generated askpass script."""

    def test_password_prompt_matches(self, tmp_path):
        import subprocess

        env = create_askpass("secret", askpass_file=tmp_path / "askpass")
        result = subprocess.run(
            [env["SSH_ASKPASS"], "Password: "],
            capture_output=True,
            text=True,
            env={"__SSH_CONCIERGE_PW": "secret"},
        )
        assert result.stdout.rstrip("\n") == "secret"

    def test_custom_password_pattern(self, tmp_path):
        import subprocess

        env = create_askpass(
            "secret",
            askpass_file=tmp_path / "askpass",
            password_patterns=("*credentials*",),
        )
        result = subprocess.run(
            [env["SSH_ASKPASS"], "Enter credentials: "],
            capture_output=True,
            text=True,
            env={"__SSH_CONCIERGE_PW": "secret"},
        )
        assert result.stdout.rstrip("\n") == "secret"

    def test_otp_prompt_falls_through_to_tty(self, tmp_path):
        """OTP prompt without __SSH_CONCIERGE_OTP tries to use tty (fails in test)."""
        import subprocess

        env = create_askpass(
            "secret",
            askpass_file=tmp_path / "askpass",
            otp_patterns=("*erification*code*",),
        )
        result = subprocess.run(
            [env["SSH_ASKPASS"], "Verification code: "],
            capture_output=True,
            text=True,
            env={"__SSH_CONCIERGE_PW": "secret"},
        )
        # Without tty, script will fail — but should NOT output the password
        assert "secret" not in result.stdout

    def test_per_host_password_prompt_override(self, tmp_path):
        import subprocess

        env = create_askpass(
            "secret",
            askpass_file=tmp_path / "askpass",
            password_patterns=("*assword*",),
            pw_prompt="*enter credentials*",
        )
        assert env["__SSH_CONCIERGE_PW_PROMPT"] == "*enter credentials*"
        result = subprocess.run(
            [env["SSH_ASKPASS"], "enter credentials: "],
            capture_output=True,
            text=True,
            env={
                "__SSH_CONCIERGE_PW": "secret",
                "__SSH_CONCIERGE_PW_PROMPT": "*enter credentials*",
            },
        )
        assert result.stdout.rstrip("\n") == "secret"

    def test_per_host_override_takes_priority(self, tmp_path):
        """Per-host override matches before global patterns."""
        import subprocess

        # Global patterns would NOT match 'Custom prompt:'
        env = create_askpass(
            "secret",
            askpass_file=tmp_path / "askpass",
            password_patterns=("*assword*",),
            pw_prompt="*Custom*",
        )
        result = subprocess.run(
            [env["SSH_ASKPASS"], "Custom prompt: "],
            capture_output=True,
            text=True,
            env={
                "__SSH_CONCIERGE_PW": "secret",
                "__SSH_CONCIERGE_PW_PROMPT": "*Custom*",
            },
        )
        assert result.stdout.rstrip("\n") == "secret"

    def test_unrecognized_prompt_shows_prefix(self, tmp_path):
        """Unrecognized prompts are prefixed with [unrecognized prompt]."""
        import subprocess

        env = create_askpass("secret", askpass_file=tmp_path / "askpass")
        result = subprocess.run(
            [env["SSH_ASKPASS"], "Something else: "],
            capture_output=True,
            text=True,
            env={"__SSH_CONCIERGE_PW": "secret"},
        )
        # Falls through to catch-all which tries /dev/tty — no tty in test
        assert "secret" not in result.stdout

    def test_no_pw_prompt_env_var_when_not_set(self, tmp_path):
        env = create_askpass("secret", askpass_file=tmp_path / "askpass")
        assert "__SSH_CONCIERGE_PW_PROMPT" not in env
        assert "__SSH_CONCIERGE_OTP_PROMPT" not in env

    def test_otp_prompt_env_var_when_set(self, tmp_path):
        env = create_askpass(
            "secret",
            askpass_file=tmp_path / "askpass",
            otp_prompt="*verification*",
        )
        assert env["__SSH_CONCIERGE_OTP_PROMPT"] == "*verification*"

    def test_otp_env_var_set_when_provided(self, tmp_path):
        env = create_askpass("secret", askpass_file=tmp_path / "askpass", otp="123456")
        assert env["__SSH_CONCIERGE_OTP"] == "123456"

    def test_otp_env_var_absent_when_not_provided(self, tmp_path):
        env = create_askpass("secret", askpass_file=tmp_path / "askpass")
        assert "__SSH_CONCIERGE_OTP" not in env

    def test_otp_env_var_absent_when_none(self, tmp_path):
        env = create_askpass("secret", askpass_file=tmp_path / "askpass", otp=None)
        assert "__SSH_CONCIERGE_OTP" not in env

    def test_otp_prompt_outputs_otp_value(self, tmp_path):
        """OTP prompt with __SSH_CONCIERGE_OTP set outputs the OTP."""
        import subprocess

        env = create_askpass(
            "secret",
            askpass_file=tmp_path / "askpass",
            otp_patterns=("*erification*code*",),
            otp="987654",
        )
        result = subprocess.run(
            [env["SSH_ASKPASS"], "Verification code: "],
            capture_output=True,
            text=True,
            env={
                "__SSH_CONCIERGE_PW": "secret",
                "__SSH_CONCIERGE_OTP": "987654",
            },
        )
        assert result.stdout.rstrip("\n") == "987654"

    def test_per_host_otp_prompt_outputs_otp_value(self, tmp_path):
        """Per-host OTP prompt override with OTP value outputs the OTP."""
        import subprocess

        env = create_askpass(
            "secret",
            askpass_file=tmp_path / "askpass",
            otp_prompt="*enter code*",
            otp="112233",
        )
        result = subprocess.run(
            [env["SSH_ASKPASS"], "Please enter code: "],
            capture_output=True,
            text=True,
            env={
                "__SSH_CONCIERGE_PW": "secret",
                "__SSH_CONCIERGE_OTP": "112233",
                "__SSH_CONCIERGE_OTP_PROMPT": "*enter code*",
            },
        )
        assert result.stdout.rstrip("\n") == "112233"
