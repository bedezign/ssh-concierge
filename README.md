# ssh-concierge

**Your SSH config, fully managed from 1Password.**

Stop maintaining `~/.ssh/config` by hand. ssh-concierge reads host configurations from custom fields on your 1Password items and generates SSH config fragments automatically — keys, hostnames, users, ports, passwords, and any SSH directive, all in one place.

## Why

- **Single source of truth** — SSH key + host config live together in 1Password
- **Zero-touch connections** — passwords injected automatically via `SSH_ASKPASS`, no prompts
- **Fast** — sub-millisecond on the hot path (99% of connections hit a simple file-age check, no Python)
- **Safe** — never blocks SSH, never modifies `~/.ssh/config`, always exits 0
- **Gradual adoption** — coexists with your existing static SSH config files

## vs 1Password SSH Bookmarks

1Password has built-in [SSH Bookmarks](https://developer.1password.com/docs/ssh/bookmarks/) that pair keys to hosts and generate a config file. ssh-concierge takes a different approach — it treats 1Password as the single source of truth for your full SSH config, so every tool that speaks SSH (git, rsync, ansible, etc.) just works.

| | SSH Bookmarks | ssh-concierge |
|---|---|---|
| Key-to-host mapping | Yes | Yes |
| Generate SSH config | Yes (host + key only) | Yes (full: user, port, any directive) |
| Password injection | No | Yes (via `SSH_ASKPASS`) |
| Clipboard templates | No | Yes |
| `op://` references in fields | No | Yes (with `\|\|` fallback chains) |
| Brace expansion / regex | No | Yes (`worker{1..8}`, `s/pattern/replace/`) |
| Multiple host groups per key | No | Yes (multiple SSH Config sections) |
| Cross-item key references | No | Yes |
| Per-machine filtering | No | Yes (`on` field) |
| Deploy keys via `ssh-copy-id` | No | Yes |
| Hosts without SSH keys | No | Yes (`SSH Host` tag) |
| Custom fields for automation | No | Yes |

If you only need to connect to a few hosts from the 1Password app, Bookmarks work fine. If you manage many hosts, need password auth, or want your SSH config fully driven from 1Password, ssh-concierge is the tool.

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
- **`{{alias}}` placeholder** — `{{alias}}.example.com` expands per alias (simpler alternative to regex)
- **Any SSH directive** — `ProxyJump`, `ForwardAgent`, `LocalForward`, etc. — just add the field
- **Custom fields** — store arbitrary data for use in clipboard templates
- **Configurable** — optional TOML config for custom paths, TTL, and timeouts
- **Atomic writes + lockfile** — safe under concurrent SSH connections

## Documentation

- **[Quickstart](docs/QUICKSTART.md)** — up and running in 5 minutes
- **[Manual](docs/MANUAL.md)** — full reference for all features

## Requirements

- **Platforms**: Linux and macOS. Windows is not supported (WSL may work but is untested).
- Python 3.11+
- [1Password CLI](https://developer.1password.com/docs/cli/) (`op`) installed and signed in
- 1Password SSH agent (`~/.1password/agent.sock`)

## Install

```bash
./install.sh
```

Creates a venv, installs the package, and symlinks binaries to `~/.local/bin/`. Run `./install.sh --help` for options, `./install.sh --uninstall` to remove.

### SSH/SCP wrappers (optional)

The installer also creates `~/.local/bin/ssh` and `~/.local/bin/scp` that shadow the system binaries. These wrappers are only needed for **password injection** and **clipboard** features — they look up the host in `hostdata.json`, resolve passwords via `op read`, and set `SSH_ASKPASS` before calling the real `ssh`/`scp`.

If you only use SSH key authentication (via the 1Password agent), you don't need the wrappers. Remove them with:

```bash
rm ~/.local/bin/ssh ~/.local/bin/scp
```

See the [Quickstart](docs/QUICKSTART.md) or [Manual](docs/MANUAL.md#installation) for details.

## Development

```bash
uv sync
uv run pytest tests/ -v
```
