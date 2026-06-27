<div align="center">

# 🔒 dotprot

**Pick up where you left off — without worrying about your `.env` files.**

Lock your `.env` (and anything else you list) into a dedicated 1Password vault,
then restore it on demand. dotprot uploads the exact bytes, **verifies the copy
round-trips correctly, and only then removes the file from disk.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org)

</div>

---

## Why

You finish for the day, your project's secrets sit in a plaintext `.env`. You
come back next week (or clone the repo on another machine) and have to hunt them
down again. dotprot makes that a single command: `dotprot` tucks the files
safely into 1Password and removes them locally; `dotprot` again brings them
back, byte-for-byte. Your secrets live where they belong, and you never lose the
thread of a project.

A single self-contained binary — no runtime to install — that shells out to the
official 1Password CLI for all storage and authentication.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [The `.prot` file](#the-prot-file)
- [Safety guarantees](#safety-guarantees)
- [Development](#development)

## How it works

dotprot reads a `.prot` file in your working directory that lists which files to
protect — globs, one per line, defaulting to `.env*`. Each protected file is
stored as a 1Password **document** in a vault named `.prot`. The document IDs are
written back into your `.prot` file so the same directory can lock and unlock
repeatedly.

```
┌─────────────┐   dotprot lock    ┌──────────────────────┐
│  ./.env     │ ────────────────► │  1Password ".prot"   │
│  (on disk)  │ ◄──────────────── │  vault (documents)   │
└─────────────┘   dotprot unlock  └──────────────────────┘
```

## Requirements

- The [1Password CLI (`op`)](https://developer.1password.com/docs/cli/get-started/),
  signed in (`op signin`).

dotprot never touches your 1Password credentials — it shells out to `op`, which
handles all authentication. If you're not signed in, dotprot tells you to run
`op signin` and does nothing else.

## Install

### Homebrew

```sh
brew install jstilwell/tap/dotprot
```

### Cargo

```sh
cargo install dotprot
```

### Prebuilt binaries

Download the binary for your platform from the
[releases page](https://github.com/jstilwell/dotprot/releases) and put it on
your `PATH`.

### From source

```sh
git clone https://github.com/jstilwell/dotprot
cd dotprot
cargo build --release      # binary at target/release/dotprot
```

## Usage

```sh
dotprot           # smart toggle: lock if files present, unlock if absent
dotprot lock      # force lock:   upload → verify → delete from disk
dotprot unlock    # force unlock: restore files from 1Password
dotprot --keep    # lock, but keep the originals on disk (don't delete)
dotprot setup     # optional: pre-create the .prot vault in 1Password
```

You don't have to run `dotprot setup` first. The very first `dotprot` (or
`dotprot lock`) in a directory creates the `.prot` vault automatically if it
doesn't exist, tells you it did, and carries on:

```text
$ dotprot
Created 1Password vault ".prot" (abc123...).
(one-time setup — future runs reuse it)
Created .prot (protecting: .env*).
  locked .env -> 1Password
Locked 1 file(s) into vault ".prot".
```

### The toggle

Running bare `dotprot` figures out which way to go from what's on disk:

| State                                   | What `dotprot` does            |
| --------------------------------------- | ------------------------------ |
| Protected files are **present**         | Locks them into 1Password      |
| Protected files are **missing**         | Restores them from 1Password   |
| **Mixed** (some present, some missing)  | Stops and asks you to be explicit (`dotprot lock` / `dotprot unlock`) |

### Trying it safely with `--keep`

Before trusting dotprot to delete anything, upload-and-verify without removing
the originals:

```sh
dotprot --keep    # .env is copied to 1Password and verified, but stays on disk
# open the .prot vault in the 1Password app and confirm .env is there
dotprot lock      # now remove the local copy
```

## The `.prot` file

Auto-created on first lock. dotprot owns everything above the sentinel and
rewrites it freely; the file list below the sentinel is yours to edit:

```text
# dotprot — managed below, do not edit
vault: abcd1234efgh5678
doc .env: 6yx...
doc config/secrets.json: q9z...
# ---- your files (edit below) ----
.env*
config/secrets.json
```

> **Tip:** commit `.prot` to version control. It contains only 1Password
> vault/item IDs — **no secrets** — and lets teammates `dotprot unlock` the same
> files, given access to the vault.

## Safety guarantees

dotprot's whole reason to exist is to make secrets *easier* to manage, never to
put them at risk. The design centers on one rule: **a local file is deleted only
after a verified, recoverable copy exists in 1Password.**

- **Verify-then-delete.** A file is removed from disk only after its 1Password
  copy is uploaded, **read back, and confirmed byte-identical**. Any failure in
  that chain leaves the original untouched. Use `--keep` to skip deletion
  entirely.
- **Scoped to the `.prot` vault only.** Every 1Password operation is scoped with
  `--vault .prot`. dotprot **never deletes 1Password items in normal
  operation** — lock creates/updates documents, unlock only reads them.
- **Incremental persistence.** `.prot` is updated after *each* file locks, so an
  interruption mid-batch leaves you in a consistent, recoverable state.
- **Backups are kept.** Documents stay in 1Password after unlock, so a directory
  stays re-lockable and you always have a copy. Re-locking overwrites the
  existing document in place.
- **Stable titles.** Document titles are the file's **absolute path**, so
  they're easy to find in the 1Password UI and never collide across directories
  or machines.
- **Minimal on-disk exposure.** Secrets are handed to `op` via a short-lived
  `0600` temp file that's deleted immediately afterward (the 1Password CLI does
  not reliably accept piped stdin).

## Development

```sh
cargo build            # debug build
cargo test             # run unit tests
cargo clippy           # lint
cargo build --release  # optimized binary
```

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

[MIT](LICENSE)
