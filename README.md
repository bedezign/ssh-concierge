# ssh-concierge

Dynamic SSH configuration provider backed by 1Password.

Reads SSH host configurations from custom fields on 1Password items and generates SSH config fragments automatically. Your SSH keys and host configs live together in 1Password — ssh-concierge bridges them to `~/.ssh/config` at connection time.

## Why

- **Single source of truth**: SSH key + host config in one place (1Password)
- **No manual config files**: Add a section to your 1Password item, run `--generate`, done
- **Fast**: Sub-millisecond on the hot path (99% of connections) — no Python, no 1Password queries
- **Safe**: Never blocks SSH, never modifies `~/.ssh/config`, always exits 0
- **Gradual migration**: Coexists with static SSH config files

## How it works

```
~/.ssh/config:
  Match host * exec "ssh-concierge %h"   ← checks if config is fresh (zsh, <1ms)
    Include <XDG_RUNTIME_DIR>/ssh-concierge/hosts.conf  ← pre-generated from 1Password
  Include ~/.ssh/static/config            ← existing configs still work
```

On first connection (or after 1-hour cache expires), the Python core queries 1Password for all managed items, generates a complete config file with all managed hosts, and dumps public keys for `IdentityFile` hinting. Every subsequent connection just checks the file's age and exits.

## Quick example

Add an "SSH Config" section to any SSH Key item in 1Password:

| Field | Value |
|-------|-------|
| aliases | `myserver, myserver.example.com` |
| hostname | `203.0.113.42` |
| user | `deploy` |

Then:

```bash
ssh-concierge --generate
ssh myserver   # connects to 203.0.113.42 as deploy, using the item's key
```

## Features

- **Multiple hosts per key**: Add multiple `SSH Config: <name>` sections to one item
- **Hosts without keys**: Tag any item `SSH Host` to manage password-auth hosts too
- **Transparent password auth**: Add a `password` field with an `op://` reference — SSH/SCP connects without prompts
- **`op://` references in any field**: Hostname, user, or any directive can reference 1Password values
- **`||` fallback chains**: `op://./hostname||10.0.0.1` — try the reference, fall back to a literal
- **Sensitive fields**: `ops://` prefix marks fields that should never be cached resolved on disk
- **Cross-item key references**: Use a `key` field to share SSH keys across items
- **Deploy keys**: `--deploy-key worker1 --all` installs pubkeys to hosts via `ssh-copy-id`
- **Brace expansion**: `worker{1..8}` expands to `worker1` through `worker8`
- **Regex substitution**: `s/pattern/replacement/` on any field — hostname, user, any directive
- **CyberArk PSMP support**: Generates the compound username that's impossible in static SSH config
- **Any SSH directive**: `ProxyJump`, `ForwardAgent`, `LocalForward`, etc. — just add the field
- **Atomic writes + lockfile**: Safe under concurrent SSH connections

## Documentation

- [Quickstart](docs/QUICKSTART.md) — up and running in 5 minutes
- [Manual](docs/MANUAL.md) — full reference for all features

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- [1Password CLI](https://developer.1password.com/docs/cli/) (`op`)
- 1Password SSH agent (`~/.1password/agent.sock`)
- `ssh-copy-id` (for `--deploy-key`, typically part of `openssh-client`)

## Install

```bash
# Install the Python package as a global tool (editable — code changes take effect immediately)
uv tool install --editable /path/to/ssh-concierge

# Symlink the zsh entry point (the hot-path wrapper that SSH calls)
ln -s /path/to/ssh-concierge/src/ssh-concierge ~/.local/bin/ssh-concierge
chmod +x /path/to/ssh-concierge/src/ssh-concierge

# Optional: SSH/SCP wrapper for transparent password injection
ln -s $(which ssh-concierge-wrap) ~/.local/bin/ssh
ln -s $(which ssh-concierge-wrap) ~/.local/bin/scp
```

Ensure `~/.local/bin` is before `/usr/bin` in your `$PATH`.

This gives you:
- `ssh-concierge` — the zsh wrapper (used by SSH's `Match exec`, handles caching)
- `ssh-concierge-py` — the Python CLI directly (used by the wrapper, also usable standalone)
- `ssh` / `scp` — optional wrappers that inject passwords from 1Password transparently

## Development

```bash
uv sync
uv run pytest tests/ -v
```
