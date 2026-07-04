# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Delete only what was uploaded.** `lock` now re-reads each file immediately
  before deleting it and aborts (leaving the file in place) if it changed
  during the upload/verify round-trip — previously an edit made in that window
  (e.g. by a dev server rewriting `.env`) would be deleted even though the
  verified 1Password copy predated it.
- **Hardened restore path.** `unlock` now refuses to restore a `.prot` entry
  whose path is absolute or contains `..` (a tampered `.prot` could otherwise
  direct vault content to an arbitrary path outside the project), and restored
  files are opened with `O_CREAT|O_EXCL` so a planted symlink — even a dangling
  one — can no longer redirect a restored secret to another location. Neither
  check affects normal lock/unlock round-trips, which only ever record plain
  relative paths.

## [0.3.0] - 2026-06-28

### Added

- When you're not signed in to 1Password, dotprot now offers to sign you in
  instead of just erroring out: at an interactive terminal it prompts
  `Sign in now? [y/N]` and, on confirmation, runs `op signin` for you and then
  continues with the original command. In a non-interactive context (CI, a
  pipe) it never prompts or hangs — it falls back to the previous clear
  `Run \`op signin\` first.` error.

## [0.2.0] - 2026-06-28

### Changed

- Re-locking an existing file now also refreshes its 1Password document
  **title** (the file's absolute path), so a moved file's vault entry no longer
  keeps a stale title.
- The bare `dotprot` "mixed state" error now lists exactly which recorded files
  are present and which are missing, instead of just reporting counts.
- During `lock`, a file-glob entry that can't be read (e.g. a permission error
  while walking a directory) now prints a `warning: could not read … — skipped`
  line instead of being dropped silently. One unreadable entry still doesn't
  abort the lock, but it's no longer invisible — a file you meant to protect
  won't be skipped without you knowing.

### Security

- The `.prot` state file is now written with owner-only (`0600`) permissions on
  Unix when created, matching every other file dotprot writes. It holds no
  secrets — only vault and document IDs — but it maps which 1Password documents
  back this project, so it's no longer left world-readable. An existing
  `.prot`'s permissions are left untouched.

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
[Unreleased]: https://github.com/jstilwell/dotprot/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jstilwell/dotprot/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jstilwell/dotprot/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jstilwell/dotprot/releases/tag/v0.1.0
