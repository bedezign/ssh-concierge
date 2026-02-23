# Manual

## How it works

ssh-concierge has two layers:

- A **zsh entry point** called by SSH's `Match exec` on every connection. It checks if the generated config file is fresh (< 1 hour old). If yes, it exits immediately — sub-millisecond, no Python involved.
- A **Python core** that queries 1Password, builds SSH config fragments, and dumps public keys. Only runs on the cold path (first connection or expired cache).

SSH never blocks. The entry point always exits 0, even if 1Password is locked or the `op` CLI fails.

## Installation

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- [1Password CLI](https://developer.1password.com/docs/cli/) (`op`) installed and signed in
- 1Password SSH agent enabled (`~/.1password/agent.sock`)
- `ssh-copy-id` (for `--deploy-key`, typically part of `openssh-client`)

### Setup

```bash
# Install the Python CLI as a global tool (editable — code changes take effect immediately)
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

| Command | What | Used by |
|---------|------|---------|
| `ssh-concierge` | Zsh wrapper — hot path caching + delegates to Python | SSH's `Match exec`, your shell |
| `ssh-concierge-py` | Python CLI directly | The zsh wrapper, or you directly |
| `ssh` / `scp` | Optional wrappers that inject passwords from 1Password | Your shell (replaces `/usr/bin/ssh` in PATH) |

### Updating

Because `--editable` is used, pulling new code takes effect immediately — no reinstall needed. If `pyproject.toml` changes (new dependencies, entry points), re-run:

```bash
uv tool install --editable /path/to/ssh-concierge --force
```

## 1Password item structure

An item becomes managed when **both** conditions are met:

1. **Candidate selection** — the item is either:
   - An **SSH Key** item (automatically included, no tag needed), or
   - Any item tagged **`SSH Host`** (Server, Login, Secure Note, etc.)
2. **Config presence** — the item has a section starting with "SSH Config" containing at least an `aliases` field

SSH Key items get `IdentityFile` + `IdentitiesOnly` directives. Items without keys (tagged `SSH Host`) produce Host blocks without key hints — SSH uses password auth or the 1Password agent.

### Single host

Add a section named **SSH Config** with these fields:

| Field | Required | Description |
|-------|----------|-------------|
| `aliases` | Yes | Comma-separated names to match. These become the `Host` line in SSH config. |
| `hostname` | No | IP or FQDN. Defaults to the first alias. Supports SSH's `%h` token. |
| `port` | No | SSH port. |
| `user` | No | Login user. |
| `password` | No | Password for auth. See [Password authentication](#password-authentication). |
| Any SSH directive | No | Added verbatim. E.g., `ProxyJump`, `ForwardAgent`, `LocalForward`. |

The item's public key is automatically dumped and referenced via `IdentityFile` + `IdentitiesOnly yes`.

### Multiple host groups per key

When multiple hosts share one SSH key, add multiple sections to the same item. Each section name must start with `SSH Config`:

- `SSH Config` — single host (simplest case)
- `SSH Config: production` — one group
- `SSH Config: staging` — another group

Each section has its own `aliases`, `hostname`, `user`, etc. All sections share the item's SSH key.

**Example**: An appliance with 11 servers sharing one key:

| Section | Field | Value |
|---------|-------|-------|
| SSH Config: fqdn | aliases | `*.cluster1.example.com` |
| SSH Config: fqdn | user | `admin` |
| SSH Config: short | aliases | `master{1,2}, worker{1..8}, utility1` |
| SSH Config: short | hostname | `%h.cluster1.example.com` |
| SSH Config: short | user | `admin` |

## Aliases

The `aliases` field supports:

### Plain names
```
prod, prod-web-01, production.example.com
```

### SSH wildcard patterns
```
*.cluster1.example.com
worker?
```

### Brace expansion

Ranges and lists are expanded at generation time (SSH never sees braces):

```
worker{1..8}           → worker1 worker2 worker3 ... worker8
node{1,2,3}            → node1 node2 node3
{master,worker}1       → master1 worker1
prdworker{1..8}        → prdworker1 prdworker2 ... prdworker8
```

Commas inside braces are not confused with the alias separator.

## Regex substitution

Any field value starting with `s/` is treated as a regex substitution applied to each alias individually. This generates one `Host` block per alias with the computed value. Works on `hostname`, `user`, and any extra directive.

**Format**: `s/pattern/replacement/`

### Hostname example

You want `prdmaster1` to connect to `master1.cluster1prd.example.com`:

```
aliases:  prdmaster{1,2}, prdworker{1..8}, prdutility1
hostname: s/^prd(.+)/\1.cluster1prd.example.com/
```

Generates:
```ssh-config
Host prdmaster1
    HostName master1.cluster1prd.example.com
Host prdmaster2
    HostName master2.cluster1prd.example.com
...
```

### User example (CyberArk PSMP)

CyberArk PSMP encodes the target host in the SSH username. This is impossible to express in static SSH config (the `%` in the username breaks token expansion). ssh-concierge generates individual Host blocks with the full username:

```
aliases:  server{1..5}
hostname: pam-gateway.example.com
user:     s/(.+)/jdoe@pajdoe%corp.example.com@\1.example.com/
```

Generates:
```ssh-config
Host server1
    HostName pam-gateway.example.com
    User jdoe@pajdoe%corp.example.com@server1.example.com

Host server2
    HostName pam-gateway.example.com
    User jdoe@pajdoe%corp.example.com@server2.example.com
...
```

Now `ssh server1` connects through PSMP without remembering the compound username.

> **Note**: The `%` in the generated `User` value may or may not work depending on your OpenSSH version's token expansion behavior. If it doesn't, ssh-concierge can generate a ProxyCommand-based workaround instead (not yet implemented).

### Mixing regex and static fields

Regex triggers per-alias expansion for the entire Host block. Fields without regex are copied as-is to each expanded block:

```
aliases:  server{1..3}
hostname: s/(.+)/\1.internal.example.com/
user:     deploy
port:     22
```

Each generated block gets its own computed `HostName` but shares the same `User` and `Port`.

Without regex on any field, all aliases share a single `Host` line (standard SSH behavior).

## Password authentication

Hosts that require password auth can store an `op://` reference in the `password` field. The SSH/SCP wrapper resolves it at connection time via `op read` and injects it via `SSH_ASKPASS`.

### Password field formats

| Format | Example | Behavior |
|--------|---------|----------|
| `op://Vault/Item/field` | `op://Work/ServerLogin/password` | Used directly with `op read` |
| `op://Vault/Item` | `op://Work/ServerLogin` | `/password` appended automatically |
| `op://./field` | `op://./password` | Expanded using the current item's vault/item IDs |
| Literal | `hunter2` | Stored as an `op://` reference back to the field (no plaintext on disk) |

**Recommended**: Use `op://Vault/Item/password` to reference a Login item's password, or `op://./password` to reference the current item's own password field.

### How it works

1. `ssh-concierge --generate` builds `passwords.json` mapping each alias to its `op://` reference
2. The `ssh`/`scp` wrapper parses your command to extract the target hostname
3. It looks up the hostname in `passwords.json`
4. If found, it calls `op read` to resolve the `op://` reference to the actual password
5. It creates a temporary askpass script and sets `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force`
6. SSH uses the askpass script instead of prompting interactively

If any step fails (no entry in `passwords.json`, `op read` fails, 1Password is locked), the wrapper falls back to normal interactive auth.

### Security

- `passwords.json` contains only `op://` references — never plaintext passwords
- The askpass temp script is created with `0700` permissions and deleted after SSH exits
- Passwords are resolved on demand; nothing is cached to disk

### Setup

Install the SSH/SCP wrapper symlinks (one-time):

```bash
ln -s $(which ssh-concierge-wrap) ~/.local/bin/ssh
ln -s $(which ssh-concierge-wrap) ~/.local/bin/scp
```

Ensure `~/.local/bin` comes before `/usr/bin` in your `$PATH`. The wrapper finds the real `ssh`/`scp` by scanning PATH and skipping itself.

### Removing the wrapper

```bash
rm ~/.local/bin/ssh ~/.local/bin/scp
```

SSH and SCP revert to `/usr/bin/ssh` and `/usr/bin/scp` immediately.

## CLI commands

```bash
ssh-concierge --generate              # Force regenerate from 1Password
ssh-concierge --flush                  # Delete runtime config entirely
ssh-concierge --list                   # List all managed Host entries
ssh-concierge --status                 # Show config path, age, host count
ssh-concierge --deploy-key ALIAS       # Deploy SSH key to a host via ssh-copy-id
ssh-concierge --deploy-key ALIAS --all # Deploy to all sibling hosts in the same section
```

The zsh entry point accepts all flags and delegates to Python.

### Deploy key

`--deploy-key` automates `ssh-copy-id` using host/key information from 1Password. It finds the host by alias, locates the associated public key, and runs `ssh-copy-id -i <key> [user@]host [-p port]`. If the host has a `password` field, it's injected automatically via `SSH_ASKPASS`. Otherwise, the user types the password interactively.

With `--all`, it also deploys to all **sibling hosts** — hosts from the same 1Password section with the same SSH key. Wildcard aliases (e.g., `*.example.com`) are excluded from `--all` expansion.

If the runtime config doesn't exist yet, `--deploy-key` generates it automatically.

## Runtime config

Generated at `$XDG_RUNTIME_DIR/ssh-concierge/`:

```
$XDG_RUNTIME_DIR/ssh-concierge/
├── hosts.conf              # SSH config fragment (the Include target)
├── passwords.json          # alias → op:// reference map (0600 permissions)
├── keys/
│   ├── SHA256:abc123.pub   # Public keys for IdentityFile
│   └── SHA256:def456.pub
└── .lock                   # Prevents concurrent generation races
```

- `hosts.conf` is written atomically (temp file + rename) — no partial reads.
- `passwords.json` stores only `op://` references, never plaintext passwords. Gets `0600` permissions.
- Public keys get `0644` permissions.
- The `.lock` file uses `fcntl.flock` so parallel SSH connections don't corrupt the config.

## Cache behavior

- **TTL**: 1 hour. The zsh entry point checks the mtime of `hosts.conf`.
- **No background refresh**. The cache is populated on the first SSH connection after expiry.
- **Manual refresh**: `ssh-concierge --generate` (after modifying items in 1Password).
- **Clear cache**: `ssh-concierge --flush` (next SSH connection triggers a cold path).

## Coexistence with static config

ssh-concierge does not touch `~/.ssh/config` or any static config files. The `Match exec` + `Include` block sits above your existing `Include` lines. Hosts defined in static configs continue to work — SSH processes them in order, and the first match wins.

To migrate a host from static config to 1Password: add the SSH Config section to the key item, run `--generate`, then remove the static entry.

## Troubleshooting

**No hosts appearing after `--generate`**:
- For SSH Key items: verify the item has a section starting with `SSH Config`.
- For non-key items: verify the item is tagged `SSH Host` and has an `SSH Config` section.
- Check the section has an `aliases` field with a non-empty value.
- Run `op item list --format json | python3 -c "import sys,json; print(len(json.load(sys.stdin)))"` to confirm `op` is signed in.

**1Password locked / not signed in**:
- The cold path fails silently (exit 0). SSH falls through to static config.
- Sign in with `op signin` or unlock 1Password, then run `ssh-concierge --generate`.

**Stale config**:
- Run `ssh-concierge --status` to check age.
- Run `ssh-concierge --generate` to force refresh.
