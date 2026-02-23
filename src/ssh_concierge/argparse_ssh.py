"""SSH and SCP argument parsing — extract hostname from command-line args."""

from __future__ import annotations

# ssh options that consume the next argument
_SSH_OPTS_WITH_ARG = frozenset(
    'b c D E e F I i J L l m O o p Q R S W w'.split()
)

# scp options that consume the next argument
_SCP_OPTS_WITH_ARG = frozenset(
    'c D F i J l o P S'.split()
)


def _strip_user(destination: str) -> str:
    """Strip user@ prefix from a destination string."""
    if '@' in destination:
        return destination.split('@', 1)[1]
    return destination


def extract_ssh_host(argv: list[str]) -> str | None:
    """Extract hostname from ssh command-line args.

    Parses: ssh [options] [user@]hostname [command...]
    Returns the hostname (without user@ prefix), or None if not found.
    """
    i = 0
    while i < len(argv):
        arg = argv[i]

        if arg == '--':
            # Next arg after -- is the hostname
            if i + 1 < len(argv):
                return _strip_user(argv[i + 1])
            return None

        if arg.startswith('-') and len(arg) >= 2 and not arg.startswith('--'):
            flag = arg[1]
            if flag in _SSH_OPTS_WITH_ARG:
                if len(arg) > 2:
                    # -pNNNN style (option value glued to flag)
                    i += 1
                else:
                    # -p NNNN style (next arg is the value)
                    i += 2
                continue
            # Boolean flag (e.g. -v, -N, -T)
            # Could be combined: -vvv or -NTv
            i += 1
            continue

        # First non-option arg is [user@]hostname
        return _strip_user(arg)

    return None


def extract_scp_host(argv: list[str]) -> str | None:
    """Extract first remote hostname from scp command-line args.

    Parses: scp [options] source... target
    Remote paths match [user@]host:path
    Returns the hostname from the first remote path found, or None.
    """
    i = 0
    while i < len(argv):
        arg = argv[i]

        if arg.startswith('-') and len(arg) >= 2:
            flag = arg[1]
            if flag in _SCP_OPTS_WITH_ARG:
                if len(arg) > 2:
                    i += 1
                else:
                    i += 2
                continue
            i += 1
            continue

        # Positional arg — check if it's a remote path (contains : but not /)
        # A remote path looks like [user@]host:path
        # Skip if it starts with / (local absolute path) or has no :
        if ':' in arg and not arg.startswith('/'):
            host_part = arg.split(':', 1)[0]
            return _strip_user(host_part)

        i += 1

    return None
