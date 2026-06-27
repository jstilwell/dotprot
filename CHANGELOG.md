# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-06-27

Initial release. A self-contained Rust binary that locks `.env` (and any other
files listed in `.prot`) into a dedicated 1Password vault and restores them on
demand.

### Added

- `dotprot` (bare) — smart toggle that **locks** protected files when they're
  present on disk and **unlocks** them when they're missing.
- `dotprot lock` — upload each protected file to 1Password, verify the copy
  round-trips byte-for-byte, then delete the local original.
- `dotprot unlock` — restore protected files from 1Password (documents are kept
  so the directory stays re-lockable).
- `dotprot setup` — pre-create the `.prot` 1Password vault (optional).
- `--keep` flag — upload and verify without deleting the local originals, for
  safely confirming the vault copy before trusting deletion.
- Auto-creation of the `.prot` vault on first run, announced clearly as a
  one-time setup step.
- Auto-creation of a `.prot` config file (defaulting to the `.env*` glob) on
  first lock.
- Glob support in `.prot` for selecting files to protect.
- Mixed-state detection: bare `dotprot` refuses to guess when some protected
  files are present and others are missing, directing the user to an explicit
  `lock`/`unlock`.
- Release distribution via [cargo-dist]: cross-compiled binaries for macOS
  (arm64/x86_64), Linux (arm64/x86_64), and Windows (x86_64), attached to a
  tagged GitHub release.
- Install channels: a Homebrew tap (`brew install jstilwell/tap/dotprot`),
  shell/PowerShell one-line installers, and crates.io (`cargo install dotprot`).

### Known limitations

- **Windows:** the owner-only (`0600`) file-permission hardening is enforced on
  macOS and Linux only. On Windows the temp and restored files use default ACLs.
  The verify-then-delete guarantee and `.prot`-vault scoping hold on all
  platforms.

### Security

- **Verify-then-delete:** local files are removed only after their 1Password
  copy is uploaded, read back, and confirmed byte-identical.
- **Vault scoping:** every 1Password operation is scoped to the `.prot` vault;
  no delete operations run during normal lock/unlock.
- **Incremental persistence:** `.prot` is written after each file locks, keeping
  state recoverable if an operation is interrupted.
- Secrets are passed to `op` via a short-lived `0600` temp file that is removed
  immediately, and restored files are written with `0600` permissions.

[cargo-dist]: https://github.com/axodotdev/cargo-dist
[Unreleased]: https://github.com/jstilwell/dotprot/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jstilwell/dotprot/releases/tag/v0.1.0
