# ssh-concierge

**Your SSH config, fully managed from 1Password.**

Stop maintaining `~/.ssh/config` by hand. ssh-concierge reads host configurations from custom fields on your 1Password items and generates SSH config fragments automatically — keys, hostnames, users, ports, passwords, and any SSH directive, all in one place.

## Why

- **Single source of truth** — SSH key + host config live together in 1Password
- **Zero-touch connections** — passwords injected automatically via `SSH_ASKPASS`, no prompts
- **Fast** — sub-millisecond on the hot path (99% of connections hit a simple file-age check, no Python)
- **Safe** — never blocks SSH, never modifies `~/.ssh/config`, always exits 0
- **Gradual adoption** — coexists with your existing static SSH config files

## How it works

```
~/.ssh/config:
  Match host * exec "ssh-concierge %h"   ← checks if config is fresh (<1ms)
    Include .../ssh-concierge/hosts.conf  ← pre-generated from 1Password
  Include ~/.ssh/static/config            ← existing configs still work
```

On first connection (or after the 1-hour cache expires), the Python core queries 1Password for all managed items, generates a complete config, and dumps public keys. Every subsequent connection just checks the file's age and exits.

## Quick start

1. Add an **SSH Config** section to any SSH Key item in 1Password:

   | Field | Value |
   |-------|-------|
   | aliases | `myserver, myserver.example.com` |
   | hostname | `203.0.113.42` |
   | user | `deploy` |

2. Generate and connect:

   ```bash
   ssh-concierge --generate
   ssh myserver   # → 203.0.113.42 as deploy, using the item's key
   ```

### What gets generated

```ssh-config
# ssh-concierge — generated from 1Password
# Do not edit — regenerated automatically

Host myserver myserver.example.com
    HostName 203.0.113.42
    User deploy
    IdentityFile ~/.../keys/SHA256:abc123.pub
```

### Not just SSH keys

Any 1Password item — Server, Login, Secure Note — can manage a host. Tag it **`SSH Host`**, add an SSH Config section, and optionally point it at an existing key with the `key` field. This covers password-only hosts, shared keys across items, and hosts that use the 1Password SSH agent directly.

## Features

- **Multiple hosts per key** — add multiple `SSH Config: <name>` sections to one item
- **Any item type as host** — tag non-key items `SSH Host` for password-auth or agent-based hosts
- **Transparent password auth** — `op://` reference in `password` field, SSH/SCP connects without prompts
- **Clipboard injection** — auto-copy commands/passwords to clipboard on connect (e.g., `sudo -i\n{password}`)
- **`op://` references in any field** — hostname, user, or any directive can reference 1Password values
- **`||` fallback chains** — `op://./hostname||10.0.0.1` — try the reference, fall back to a literal
- **Sensitive fields** — `ops://` prefix ensures values are never cached on disk
- **Per-host filtering** — `on` field limits config generation to specific machines
- **Cross-item key references** — `key` field shares SSH keys across items
- **Deploy keys** — `--deploy-key worker1 --all` installs pubkeys via `ssh-copy-id`
- **Brace expansion** — `worker{1..8}` expands to `worker1` through `worker8`
- **Regex substitution** — `s/pattern/replacement/` on any field for per-alias expansion
- **Any SSH directive** — `ProxyJump`, `ForwardAgent`, `LocalForward`, etc. — just add the field
- **Custom fields** — store arbitrary data for use in clipboard templates
- **Atomic writes + lockfile** — safe under concurrent SSH connections

## Documentation

- **[Quickstart](docs/QUICKSTART.md)** — up and running in 5 minutes
- **[Manual](docs/MANUAL.md)** — full reference for all features

## Requirements

- Python 3.11+
- [1Password CLI](https://developer.1password.com/docs/cli/) (`op`) installed and signed in
- 1Password SSH agent (`~/.1password/agent.sock`)

## Install

```bash
./install.sh
```

Creates a venv, installs the package, and symlinks binaries to `~/.local/bin/`. Run `./install.sh --help` for options, `./install.sh --uninstall` to remove.

See the [Quickstart](docs/QUICKSTART.md) or [Manual](docs/MANUAL.md#installation) for details.

## Development

```bash
uv sync
uv run pytest tests/ -v
```
