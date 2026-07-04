# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Local `.prot` backups and a `dotprot restore` command.** Every time dotprot
  writes a project's `.prot`, it now mirrors it to
  `~/.prot/backups/<absolute project path>/.prot` (macOS, Linux, and Windows).
  A new `dotprot restore` command copies the backup back into the current
  directory if `.prot` was lost — purely local, no 1Password sign-in needed. It
  never overwrites an existing `.prot`: identical files are a friendly no-op,
  differing ones are refused. Backups contain no secrets (vault/document IDs
  and patterns only), and a failed backup write warns without ever blocking a
  lock.

### Security

- **The recorded vault ID is verified before use.** The `vault:` ID cached in
  `.prot` is user-editable (and often committed), so lock/unlock now confirm it
  still refers to a vault actually named `.prot` before touching anything — a
  tampered or copy-pasted ID can no longer point dotprot's document writes at a
  different vault in your account. If the vault was renamed or deleted, dotprot
  stops with instructions instead of proceeding.
- **Transient 1Password failures can no longer create duplicate `.prot`
  vaults.** Only op's genuine "isn't a vault in this account" response is
  treated as "vault missing"; network/auth/ambiguity errors now propagate
  instead of silently triggering `vault create` (1Password permits duplicate
  vault names, so this could split storage across two `.prot` vaults).
- **Delete only what was uploaded.** `lock` now re-reads each file immediately
  before deleting it and aborts (leaving the file in place) if it changed
  during the upload/verify round-trip — previously an edit made in that window
  (e.g. by a dev server rewriting `.env`) would be deleted even though the
  verified 1Password copy predated it.
- **Hardened restore path.** `unlock` now accepts only plain relative `.prot`
  entry paths — absolute paths, `..` components, and rooted Windows paths like
  `\Users\x` (which `Path::join` would otherwise resolve outside the project)
  are all refused, and every recorded path is validated **before** the first
  file is restored, so a tampered `.prot` aborts atomically instead of after a
  partial restore. The bare toggle applies the same validation before probing
  any recorded path. Restored files are opened with `O_CREAT|O_EXCL` so a
  planted symlink — even a dangling one — can no longer redirect a restored
  secret to another location. None of this affects normal lock/unlock
  round-trips, which only ever record plain relative paths.

- **No silent skips during lock.** A `.prot` pattern that matches files
  **outside** the working directory (e.g. `../shared/.env`) now prints a loud
  warning instead of being skipped silently — the file was never protected,
  but the user had no way to know it was still sitting in plaintext. A matched
  filename containing control characters (e.g. a newline) or leading/trailing
  whitespace is likewise skipped **with a warning**: either would corrupt or
  mistranslate `.prot`'s line-oriented mapping after the original file was
  already deleted, leaving the document ID recoverable only by hand from the
  1Password UI.

### Fixed

- `.prot` is now written **atomically** (temp file + rename in the same
  directory), so a crash or power loss mid-write can no longer leave it
  truncated or half-written. `.prot` is the only local map from
  already-deleted files to their 1Password documents, so corrupting it meant
  recovering document IDs by hand from the 1Password UI. An existing `.prot`'s
  permissions are still preserved; new files remain `0600` on Unix. Because a
  rename would silently replace a symlinked `.prot` (breaking the link) and
  sail over a read-only one, dotprot now **refuses to write** a `.prot` that
  is a symlink or read-only, with a clear error before anything is deleted.
- Locking now works in project directories whose path contains glob
  metacharacters (`[`, `]`, `?`, `*`) — previously the directory portion of the
  pattern was interpreted as glob syntax and matching silently failed with "No
  files match".

### Changed

- `unlock` no longer creates the `.prot` vault when it can't be found — a
  fresh, empty vault could never contain the recorded documents, so it now
  errors clearly instead. (Only `lock` and `setup` create the vault.)
- `dotprot unlock --keep` — and bare `dotprot --keep` when the toggle resolves
  to an unlock — now prints a note that `--keep` has no effect on unlock,
  instead of silently ignoring the flag.
- `dotprot lock` with nothing to lock now bails before contacting 1Password,
  instead of spending a network round-trip first.

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
