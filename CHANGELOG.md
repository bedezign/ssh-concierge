# Changelog

All notable changes to ssh-concierge are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-17

### Added

- **Pre-flight validation pass** for `--generate`, emitting warnings to stderr
  for issues that would cause SSH connections to fail. Validation runs after
  host configs are resolved but before the runtime config is written; no check
  ever blocks generation. New `--no-validate` flag to skip, and
  `--validate-refs` for opt-in deep existence checks via `op read` (cached by
  `(vault, item)` for the run). Checks include:
  - Hostname DNS resolution, with `ProxyJump` first-hop awareness
  - Duplicate aliases across items
  - Clipboard templates referencing undefined fields
  - Cross-item `key` references against the loaded item set
  - `op://` reference syntax
  - Self-reference (`op://././field`) completeness against the source item's
    field list
  - Port range sanity (1–65535)
- **Sensitive-field invariant** in `generate_runtime_config`: aborts
  generation if any field marked sensitive carries a resolved value in
  hostdata. Always-on; not affected by `--no-validate`.
- Warning when exported SSH keys are not loaded in the SSH agent. `--generate`
  runs the check on completion; `--debug ALIAS` shows per-alias agent status.
- `--config [DIRECTIVE]` to inspect resolved settings without running a
  generation.

### Changed

- **TTL now defaults to `0` (manual mode).** The shell entry point no longer
  auto-regenerates on stale config; explicit `--generate` is required to
  refresh. Set `ttl` in the config file to a positive value (e.g. `3600`) for
  time-based refresh on the first connection after expiry. `--status` and
  `--debug` report "manual" instead of "STALE" when TTL is `0`.
- The 1Password interaction layer (CLI wrapper, `FieldValue` model, `OpRef`
  parser, `||` fallback chains) is now provided by the standalone
  [op-core](https://github.com/bedezign/op-core) library, pinned by git tag in
  `pyproject.toml`.
- `cmd_generate` lists 1Password items per-vault rather than account-wide.
  `list_vaults()` is called once, then `list_items()` per vault scoped by
  category (`SSH_KEY`) and tag (`SSH Host`). Significantly faster on accounts
  with many vaults.
- Agent query failures during `--generate` are now reported instead of
  silently skipped.

### Fixed

- Edge cases in cross-item key reference resolution (self-vault refs,
  item-level vs field-level refs, malformed references) hardened with
  explicit error paths and clearer diagnostics.
