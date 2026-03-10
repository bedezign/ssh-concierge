# Manual

## How it works

ssh-concierge has two layers:

- A **shell entry point** called by SSH's `Match exec` on every connection. It checks if the generated config file is fresh (< 1 hour old). If yes, it exits immediately — sub-millisecond, no Python involved.
- A **Python core** that queries 1Password, builds SSH config fragments, and dumps public keys. Only runs on the cold path (first connection or expired cache).

The generated config lives in a [runtime directory](#runtime-config) (`$XDG_RUNTIME_DIR/ssh-concierge/`): `hosts.conf` is the SSH config fragment, `hostdata.json` caches field data for the SSH/SCP wrapper, and `keys/` holds public keys for `IdentityFile` hinting.

SSH never blocks. The entry point always exits 0, even if 1Password is locked or the `op` CLI fails.

## Installation

### Prerequisites

- **Platforms**: Linux and macOS. Windows is not supported (WSL may work but is untested).
- Python 3.11+
- [1Password CLI](https://developer.1password.com/docs/cli/) (`op`) installed and signed in
- 1Password SSH agent enabled (`~/.1password/agent.sock`)
- `ssh-copy-id` (for `--deploy-key`, typically part of `openssh-client`)

### Setup

Run the installer from the repository:

```bash
./install.sh
```

This creates a virtual environment at `~/.local/share/ssh-concierge/venv`, installs the package, and symlinks all binaries to `~/.local/bin/`. It also checks your PATH and shows SSH config instructions.

**Options**:

```
--venv PATH       Virtual environment path (default: ~/.local/share/ssh-concierge/venv)
--prefix PATH     Binary directory for symlinks (default: ~/.local/bin)
--python CMD      Python interpreter (default: auto-detect 3.11+)
--source PATH     Source directory (default: auto-detect)
--uninstall       Remove ssh-concierge (venv, symlinks)
```

After installation, you have:

| Command | What | Used by |
|---------|------|---------|
| `ssh-concierge` | Shell wrapper — hot path caching + delegates to Python | SSH's `Match exec`, your shell |
| `ssh-concierge-py` | Python CLI directly | The shell wrapper, or you directly |
| `ssh` / `scp` | Optional wrappers that inject passwords from 1Password | Your shell (replaces `/usr/bin/ssh` in PATH) |

Ensure `~/.local/bin` is before `/usr/bin` in your `$PATH`.

### Manual setup

If you prefer manual installation (e.g., for development with live code changes):

```bash
uv tool install --editable /path/to/ssh-concierge
ln -s /path/to/ssh-concierge/src/ssh-concierge ~/.local/bin/ssh-concierge
chmod +x /path/to/ssh-concierge/src/ssh-concierge
ln -s $(which ssh-concierge-wrap) ~/.local/bin/ssh
ln -s $(which ssh-concierge-wrap) ~/.local/bin/scp
```

With `--editable`, pulling new code takes effect immediately. If `pyproject.toml` changes, re-run with `--force`.

### Uninstalling

```bash
./install.sh --uninstall
```

This removes the venv and all symlinks. SSH config changes (`~/.ssh/config`) must be removed manually.

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
| `on` | No | Per-host filter. See [Per-host filtering](#per-host-filtering). |
| Any SSH directive | No | Added verbatim. E.g., `ProxyJump`, `ForwardAgent`, `LocalForward`. |
| Any other name | No | Stored as a custom field. See [Custom fields](#custom-fields). |

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

### Plain aliases vs expansion

Plain comma-separated aliases produce a **single** `Host` line — all aliases share the same settings:

```
aliases: prod, prod-web-01, production.example.com
```
```ssh-config
Host prod prod-web-01 production.example.com
    HostName 203.0.113.42
```

Brace expansion produces the same result — multiple aliases on one `Host` line — **unless** a field uses regex (`s/.../`), `{{alias}}`, or other per-alias expansion. In that case, each alias gets its own `Host` block with individually computed values. See [Regex substitution](#regex-substitution) and [`{{alias}}` placeholder](#alias-placeholder).

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

## `{{alias}}` placeholder

As a simpler alternative to regex, any field value can use `{{alias}}` as a placeholder. It's replaced with the current alias during per-alias expansion — same mechanism as regex, but without the pattern matching.

```
aliases:  worker{1..3}
hostname: {{alias}}.cluster1.example.com
```

Generates:
```ssh-config
Host worker1
    HostName worker1.cluster1.example.com
Host worker2
    HostName worker2.cluster1.example.com
Host worker3
    HostName worker3.cluster1.example.com
```

Works on any field — `hostname`, `user`, extra directives, etc. Can be combined with static fields (same rules as regex: fields without `{{alias}}` are copied as-is to each block).

> **Note**: `{{alias}}` uses double braces to avoid ambiguity with the `{field_name}` single-brace syntax used in clipboard templates.

## Percent escaping

SSH performs [token expansion](https://man.openbsd.org/ssh_config#TOKENS) on `User` and most directives — `%h`, `%p`, `%r`, etc. are replaced with connection parameters. This means a literal `%` in a field value would be misinterpreted.

ssh-concierge handles this automatically: write `\%` in your 1Password field, and it becomes `%%` in the generated config (which SSH reads as a literal `%`). `HostName` is left unescaped since `%h` there is intentional.

This matters most for CyberArk PSMP usernames (see [regex example above](#user-example-cyberark-psmp)) where `%` appears in the compound username.

## Field resolution

Any field value (not just `password`) can contain `op://` references with optional `||` fallback chains.

### Reference formats

| Format | Example | Behavior |
|--------|---------|----------|
| `op://Vault/Item/field` | `op://Work/ServerLogin/password` | Used directly with `op read` |
| `op://Vault/Item` | `op://Work/ServerLogin` | `/password` appended automatically |
| `op://./field` | `op://./hostname` | Expanded using the current item's vault/item IDs |
| `op://./Section/field` | `op://./SSH Config/password` | Self-reference with explicit section |
| `ops://...` | `ops://./password` | Same as `op://` but marks the field as **sensitive** |
| `ref\|\|fallback` | `op://./hostname\|\|10.0.0.1` | Try reference first, fall back to literal |
| Literal | `deploy` | Used as-is |

### Names with slashes or spaces

1Password item and vault names can contain `/` characters (e.g., `Laptop / SN-001234 / john.doe`). Since `op://` uses `/` as a delimiter, these names need special handling. ssh-concierge supports two approaches:

**Double quotes** — wrap the name in `"..."` to prevent `/` from being treated as a delimiter:

```
op://Work/"Laptop / SN-001234 / john.doe"/password
op://"My / Vault"/Item/field
```

**URL encoding** — use `%2F` in place of `/`:

```
op://Work/Laptop %2F SN-001234 %2F john.doe/password
op://My %2F Vault/Item/field
```

Both produce the same result. Quoting is easier to read in 1Password fields; URL encoding is what gets sent to the `op` CLI under the hood. Names with spaces work as-is — no quoting needed (e.g., `op://My Vault/My Item/password`).

This is an ssh-concierge extension — the `op` CLI itself does not support quoted names and requires UUIDs for names containing unsupported characters.

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
6. If a `password` is present, it passes the password via the `__SSH_CONCIERGE_PW` environment variable and sets `SSH_ASKPASS` to a generic askpass script + `SSH_ASKPASS_REQUIRE=force`
7. SSH calls the askpass script, which outputs the password from the environment variable — no password is ever written to disk

If any step fails (`op read` fails, 1Password is locked), the wrapper falls back to normal interactive auth.

### Security

- Sensitive fields (passwords, `ops://` references) are **never** stored resolved in `hostdata.json`
- Non-sensitive fields cache their resolved values for performance (avoids `op read` on every connection)
- The password is passed via an environment variable (`__SSH_CONCIERGE_PW`), never written to disk
- The askpass script is a static generic file (created once in `askpass_dir`, defaults to `runtime_dir`) with `0700` permissions — it only reads from the environment
- Non-password prompts (host key verification, passphrases) are passed through to the terminal — the wrapper never alters SSH behavior beyond password injection
- On systems where `askpass_dir` is on a `noexec` filesystem (common with `/tmp` on RHEL/CentOS), set `askpass_dir` to an executable filesystem in your config file. `--generate` warns if the askpass directory is on a noexec mount

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

## Per-host filtering

The `on` field restricts a host config to specific machines. When set, the config is only generated on machines whose hostname matches the filter. This is useful when you share 1Password across multiple machines but some hosts should only appear in SSH config on certain machines.

### Filter syntax

| Filter | Matches |
|--------|---------|
| *(empty)* | All machines (default) |
| `*` | All machines |
| `alpha` | Machine named `alpha` (or `alpha.example.com`) |
| `alpha, beta` | Machines named `alpha` or `beta` |
| `not alpha` | All machines except `alpha` |
| `not alpha, beta` | All machines except `alpha` and `beta` |

Matching is **case-insensitive**. A short name like `alpha` matches both `alpha` and `alpha.example.com` (FQDN). Whitespace around commas is ignored.

### Example

You have a work laptop (`work-laptop`) and a personal desktop (`home-pc`). A host should only appear on the work laptop:

| Field | Value |
|-------|-------|
| `aliases` | `internal-server` |
| `hostname` | `10.0.0.50` |
| `on` | `work-laptop` |

Running `ssh-concierge --generate` on `home-pc` skips this host entirely.

## Custom fields

Any field in the SSH Config section that isn't a known field (`aliases`, `hostname`, `port`, `user`, `password`, `clipboard`, `key`, `on`) and isn't a valid SSH directive (like `ProxyJump`, `ForwardAgent`, etc.) is stored as a **custom field**.

Custom fields are not written to `hosts.conf` (they're not SSH directives), but they are:

- Stored in `hostdata.json` with the same resolution rules as other fields (references, sensitivity, caching)
- Available as `{field_name}` placeholders in the `clipboard` template
- Shown in `--debug` output

This is useful for storing arbitrary data alongside a host — for example, a `sudo_password` or `api_key` that you want available in the clipboard template but not in SSH config.

### Example

| Field | Value |
|-------|-------|
| `aliases` | `prod-server` |
| `password` | `op://./password` |
| `sudo_password` | `ops://./sudo_password` |
| `clipboard` | `sudo -i\n{sudo_password}\n` |

The `sudo_password` field is resolved at SSH time (marked sensitive via `ops://`) and injected into the clipboard template.

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
ssh-concierge --config                 # Show all config directives and effective values
ssh-concierge --config DIRECTIVE       # Show a single config value (e.g. hosts_file, ttl)
```

The shell entry point delegates all flags to Python.

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

## Configuration

ssh-concierge works without any configuration file — all settings have sensible defaults. For customization, create a TOML file at one of these locations (checked in order):

1. `$XDG_CONFIG_HOME/ssh-concierge/config.toml`
2. `~/.config/ssh-concierge/config.toml`
3. `~/.ssh-concierge/config.toml`

### Directives

| Directive | Default | Description |
|-----------|---------|-------------|
| `runtime_dir` | `$XDG_RUNTIME_DIR/ssh-concierge` or `/tmp/ssh-concierge-$UID` | Where runtime files are generated |
| `askpass_dir` | Same as `runtime_dir` | Where the askpass script is stored |
| `ttl` | `3600` | Cache TTL in seconds |
| `op_timeout` | `120` | 1Password CLI timeout in seconds |

### Example

```toml
# ~/.config/ssh-concierge/config.toml
runtime_dir = "/run/user/1000/ssh-concierge"
ttl = 7200
```

### Querying config

Use `--config` to see the effective configuration (defaults + config file overrides):

```bash
ssh-concierge --config              # All directives
ssh-concierge --config hosts_file   # Single value
ssh-concierge --config ttl          # "3600"
```

Available directives: `config_file`, `runtime_dir`, `askpass_dir`, `hosts_file`, `hostdata_file`, `keys_dir`, `ttl`, `op_timeout`.

The shell entry point uses `--config` internally to get paths and TTL from Python, keeping a single source of truth.

## Runtime config

Generated at `$XDG_RUNTIME_DIR/ssh-concierge/` (or `runtime_dir` from config):

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

- **TTL**: 1 hour. The shell entry point checks the mtime of `hosts.conf`.
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

**Password injection fails with "permission denied"**:
- The askpass script may be on a `noexec` filesystem (common with `/tmp` on RHEL/CentOS).
- Run `ssh-concierge --generate` — it warns if the askpass directory is noexec.
- Fix: set `askpass_dir` in your config file to an executable path (e.g., `$XDG_RUNTIME_DIR/ssh-concierge`).

**Stale config**:
- Run `ssh-concierge --status` to check age.
- Run `ssh-concierge --generate` to force refresh.
