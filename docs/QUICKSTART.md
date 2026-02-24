# Quickstart

Get ssh-concierge running in 5 minutes.

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- [1Password CLI](https://developer.1password.com/docs/cli/) (`op`) installed and signed in
- 1Password SSH agent enabled (`~/.1password/agent.sock`)

## Install

```bash
# Install the Python CLI as a global tool (editable for easy development)
uv tool install --editable /path/to/ssh-concierge

# Symlink the zsh entry point (the hot-path wrapper that SSH calls)
ln -s /path/to/ssh-concierge/src/ssh-concierge ~/.local/bin/ssh-concierge
chmod +x /path/to/ssh-concierge/src/ssh-concierge

# Optional: SSH/SCP wrapper for transparent password injection
ln -s $(which ssh-concierge-wrap) ~/.local/bin/ssh
ln -s $(which ssh-concierge-wrap) ~/.local/bin/scp
```

Ensure `~/.local/bin` is before `/usr/bin` in your `$PATH`.

Verify the tools are available:

```bash
ssh-concierge --help       # zsh wrapper → delegates to Python
ssh-concierge-py --help    # Python CLI directly
```

## Configure a host in 1Password

### With an SSH key (most common)

1. Open an existing SSH Key item in 1Password (or create one)
2. Add a new section called **SSH Config**
3. Add a text field named **aliases** with the hostnames you want to use:
   ```
   myserver, myserver.example.com
   ```
4. Optionally add more fields in the same section:
   - **hostname**: `203.0.113.42` (IP or FQDN; defaults to first alias)
   - **user**: `deploy`
   - **port**: `2222`
   - **password**: `op://Vault/Item/password` (for password-auth hosts; see [Manual](MANUAL.md#password-authentication))

### Without an SSH key (password-auth hosts)

1. Create any item type (Server, Login, Secure Note, etc.)
2. Tag it **`SSH Host`**
3. Add an **SSH Config** section with the same fields as above

The `SSH Host` tag tells ssh-concierge to manage the item. Without a key, the generated Host block won't include `IdentityFile` — SSH will use password auth or the 1Password agent.

## Wire up SSH config

Add these lines near the top of `~/.ssh/config`:

```ssh-config
Host *
    IdentityAgent ~/.1password/agent.sock

Match host * exec "ssh-concierge %h"
    Include /run/user/1000/ssh-concierge/hosts.conf
```

Replace `/run/user/1000` with your `$XDG_RUNTIME_DIR` value (`echo $XDG_RUNTIME_DIR`).

Your existing `Include` lines for static configs go below this.

## Test it

```bash
# Generate the config from 1Password
ssh-concierge --generate

# Verify it picked up your host
ssh-concierge --list

# Connect
ssh myserver
```

The first connection after the cache expires (1 hour) triggers a regeneration automatically. Subsequent connections are instant.

## Force refresh

After adding or modifying hosts in 1Password:

```bash
ssh-concierge --generate
```
