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

SSH Key items get `IdentityFile` directives. Items without keys (tagged `SSH Host`) produce Host blocks without key hints — SSH uses password auth or the 1Password agent.

### Single host

Add a section named **SSH Config** with these fields:

| Field | Required | Description |
|-------|----------|-------------|
| `aliases` | Yes | Comma-separated names to match. These become the `Host` line in SSH config. |
| `hostname` | No | IP or FQDN. Defaults to the first alias. Supports SSH's `%h` token. |
| `port` | No | SSH port. |
| `user` | No | Login user. |
| `password` | No | Password for auth. See [Password authentication](#password-authentication). |
| `clipboard` | No | Template copied to clipboard on connect. See [Clipboard](#clipboard). |
| `key` | No | Cross-item SSH key reference. See [Cross-item key references](#cross-item-key-references). |
| Any SSH directive | No | Added verbatim. E.g., `ProxyJump`, `ForwardAgent`, `LocalForward`. |

The item's public key is automatically dumped and referenced via `IdentityFile`.

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

## Field resolution

Any field value (not just `password`) can contain `op://` references with optional `||` fallback chains.

### Reference formats

| Format | Example | Behavior |
|--------|---------|----------|
| `op://Vault/Item/field` | `op://Work/ServerLogin/password` | Used directly with `op read` |
| `op://Vault/Item` | `op://Work/ServerLogin` | `/password` appended automatically |
| `op://./field` | `op://./hostname` | Expanded using the current item's vault/item IDs |
| `ops://...` | `ops://./password` | Same as `op://` but marks the field as **sensitive** |
| `ref\|\|fallback` | `op://./hostname\|\|10.0.0.1` | Try reference first, fall back to literal |
| Literal | `deploy` | Used as-is |

### `||` fallback chains

Split on `||`, try each segment left-to-right. Each segment is either a reference (contains `://`) or a literal. First non-empty result wins.

```
op://./hostname||op://Vault/Backup/hostname||10.0.0.1
```

This tries three sources: the item's own hostname, a backup reference, then a hardcoded fallback.

### Sensitivity

A field is **sensitive** if:
- Any segment in the `||` chain uses the `ops://` prefix (explicit marker), OR
- The field name matches: `password`, `passwd`, `pass`, `secret`, `token`

Sensitive fields are **never** stored resolved on disk. They're kept as raw `op://` references in `hostdata.json` and resolved at SSH connection time by the wrapper.

Non-sensitive references are resolved at `--generate` time and cached in `hostdata.json`. This avoids `op read` calls on every SSH connection.

### `ops://` prefix

`ops://` is identical to `op://` for resolution (it's normalized to `op://` before calling `op read`) but marks the entire field as sensitive. Use it for any field whose resolved value should not touch disk — even non-password fields like a hostname you want to keep private.

## Password authentication

Hosts that require password auth can store an `op://` reference in the `password` field. The SSH/SCP wrapper resolves it at connection time via `op read` and injects it via `SSH_ASKPASS`.

**Recommended**: Use `op://./password` to reference the current item's own password field, or `op://Vault/Item/password` for a cross-item reference.

### How it works

1. `ssh-concierge --generate` builds `hostdata.json` mapping each alias to its fields (with original references and cached resolved values for non-sensitive fields), plus optional clipboard template
2. The `ssh`/`scp` wrapper parses your command to extract the target hostname
3. It looks up the hostname in `hostdata.json`
4. For each field, it uses the cached resolved value if available, or calls `op read` to resolve sensitive fields on the spot
5. If a `clipboard` template is present, placeholders are resolved and the result is copied to the system clipboard
6. If a `password` is present, it creates a temporary askpass script and sets `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force`
7. SSH uses the askpass script instead of prompting interactively

If any step fails (`op read` fails, 1Password is locked), the wrapper falls back to normal interactive auth.

### Security

- Sensitive fields (passwords, `ops://` references) are **never** stored resolved in `hostdata.json`
- Non-sensitive fields cache their resolved values for performance (avoids `op read` on every connection)
- The askpass temp script is created with `0700` permissions and deleted after SSH exits

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

## Clipboard

The `clipboard` field lets you automatically copy a string to the system clipboard when connecting to a host. This is useful for passwords or commands you need to paste after connecting (e.g., `sudo -i` followed by a password).

### Template syntax

The value is a template string with two features:

- **`{field_name}` placeholders** — replaced with the resolved value of another field from the same SSH Config section (e.g., `{password}`)
- **`\n` newlines** — both literal `\n` (typed as two characters in a single-line 1Password field) and real newlines (from a multi-line 1Password field) become newlines in the clipboard output

Unrecognized placeholders are left as-is.

### Example

```
clipboard: sudo -i\n{password}\n
password:  op://./password
```

When you `ssh myhost`, the clipboard contains:
```
sudo -i
hunter2

```

Three lines: the `sudo -i` command, the resolved password, and a trailing newline. Paste into the terminal after connecting.

### Clipboard without password

A host can have a `clipboard` field without a `password` field. The template is resolved and copied, and SSH connects normally (no askpass injection).

### Clipboard tool detection

The wrapper uses `wl-copy` when `$WAYLAND_DISPLAY` is set, or `xclip -selection clipboard` when `$DISPLAY` is set. If neither is available (e.g., headless), a warning is printed to stderr and the connection proceeds normally.

## Cross-item key references

The `key` field lets a non-key item (tagged `SSH Host`) reference an SSH key from another 1Password item. This is useful when multiple items should use the same key but you don't want to add multiple sections to the key item.

### Formats

| Format | Example | Behavior |
|--------|---------|----------|
| Item name | `MyKey` | Searches all vaults for an SSH Key item with this name |
| Vault/Item | `Work/MyKey` | Searches only the specified vault |

The referenced item must be an SSH Key item that is also managed by ssh-concierge (has an "SSH Config" section). The generated Host block gets `IdentityFile` pointing to the referenced key.

## CLI commands

```bash
ssh-concierge --generate              # Force regenerate from 1Password
ssh-concierge --generate --no-cache   # Regenerate, force re-resolution of all references
ssh-concierge --flush                  # Delete runtime config entirely
ssh-concierge --list                   # List all managed Host entries
ssh-concierge --status                 # Show config path, age, host count
ssh-concierge --debug ALIAS            # Show generated config block and field details
ssh-concierge --deploy-key ALIAS       # Deploy SSH key to a host via ssh-copy-id
ssh-concierge --deploy-key ALIAS --all # Deploy to all sibling hosts in the same section
```

The zsh entry point accepts all flags and delegates to Python.

### Debug

`--debug` shows the generated SSH config block for an alias, plus all field details from `hostdata.json`:

- Each field's original value, resolved value (for references), and sensitivity status
- Key references that failed to resolve are flagged with a warning
- Config age and staleness status

Useful for diagnosing why a host isn't connecting as expected — wrong vault name in a key reference, unresolved hostname, stale cached values, etc.

### Deploy key

`--deploy-key` automates `ssh-copy-id` using host/key information from 1Password. It finds the host by alias, locates the associated public key, and runs `ssh-copy-id -i <key> [user@]host [-p port]`. If the host has a `password` field, it's injected automatically via `SSH_ASKPASS`. Otherwise, the user types the password interactively.

With `--all`, it also deploys to all **sibling hosts** — hosts from the same 1Password section with the same SSH key. Wildcard aliases (e.g., `*.example.com`) are excluded from `--all` expansion.

If the runtime config doesn't exist yet, `--deploy-key` generates it automatically.

## Runtime config

Generated at `$XDG_RUNTIME_DIR/ssh-concierge/`:

```
$XDG_RUNTIME_DIR/ssh-concierge/
├── hosts.conf              # SSH config fragment (the Include target)
├── hostdata.json           # alias → {fields, clipboard, key} map
├── keys/
│   ├── SHA256:abc123.pub   # Public keys for IdentityFile
│   └── SHA256:def456.pub
└── .lock                   # Prevents concurrent generation races
```

- `hosts.conf` is written atomically (temp file + rename) — no partial reads.
- `hostdata.json` stores field data: original references, cached resolved values (for non-sensitive fields), and clipboard templates. Sensitive fields are never stored resolved.
- Public keys get `0644` permissions.
- The `.lock` file uses `fcntl.flock` so parallel SSH connections don't corrupt the config.

## Cache behavior

- **TTL**: 1 hour. The zsh entry point checks the mtime of `hosts.conf`.
- **No background refresh**. The cache is populated on the first SSH connection after expiry.
- **Manual refresh**: `ssh-concierge --generate` (after modifying items in 1Password).
- **Force re-resolution**: `ssh-concierge --generate --no-cache` (when the referenced *value* in 1Password changed but the reference itself didn't).
- **Clear cache**: `ssh-concierge --flush` (next SSH connection triggers a cold path).

### Field caching

Non-sensitive field values are cached in `hostdata.json` (original reference + resolved value). On subsequent `--generate` runs, if the original reference hasn't changed, the cached resolved value is checked against the freshly fetched item data. If the target value has changed (e.g., a `hostname` field pointing to `op://./website` where `website` was updated), the field is automatically re-resolved — no `--no-cache` needed.

This stale detection works for references to fields on the same item or other managed items (since their data is already fetched). For references to unmanaged items, use `--no-cache` to force re-resolution.

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
